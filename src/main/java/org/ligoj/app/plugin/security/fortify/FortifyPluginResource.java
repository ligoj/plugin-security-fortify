/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.security.fortify;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.Format;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.ligoj.app.api.SubscriptionStatusWithData;
import org.ligoj.app.plugin.security.SecurityResource;
import org.ligoj.app.plugin.security.SecurityServicePlugin;
import org.ligoj.app.resource.NormalizeFormat;
import org.ligoj.app.resource.plugin.AbstractToolPluginResource;
import org.ligoj.bootstrap.core.curl.CurlCacheToken;
import org.ligoj.bootstrap.core.curl.CurlRequest;
import org.ligoj.bootstrap.core.json.InMemoryPagination;
import org.ligoj.bootstrap.core.validation.ValidationJsonException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Sonar resource.
 */
@Path(FortifyPluginResource.URL)
@Service
@Produces(MediaType.APPLICATION_JSON)
public class FortifyPluginResource extends AbstractToolPluginResource implements SecurityServicePlugin {

	private static final String API_PROJECT_VERSIONS = "api/v1/projectVersions/";
	private static final String API_PROJECTS = "api/v1/projects/";
	private static final String API_TOKEN = "api/v1/auth/token";

	private static final Base64 BASE64_CODEC = new Base64(0);

	/**
	 * Plug-in key.
	 */
	public static final String URL = SecurityResource.SERVICE_URL + "/fortify";

	/**
	 * Plug-in key.
	 */
	public static final String KEY = URL.replace('/', ':').substring(1);

	/**
	 * Web site URL
	 */
	public static final String PARAMETER_URL = KEY + ":url";

	/**
	 * Fortify project identifier.
	 */
	public static final String PARAMETER_KEY = KEY + ":pkey";

	/**
	 * Fortify project-version identifier.
	 */
	public static final String PARAMETER_VERSION = KEY + ":version";

	/**
	 * Fortify user name able to perform index.
	 */
	public static final String PARAMETER_USER = KEY + ":user";

	/**
	 * Fortify user password able to perform index.
	 */
	public static final String PARAMETER_PASSWORD = KEY + ":password";

	@Autowired
	private InMemoryPagination inMemoryPagination;

	@Autowired
	private CurlCacheToken curlCacheToken;

	@Autowired
	private CacheManager cacheManager;

	@Autowired
	private ObjectMapper objectMapper;

	@Override
	public String getKey() {
		return KEY;
	}

	@SuppressWarnings("unchecked")
	@Override
	public String getVersion(final Map<String, String> parameters) throws Exception {
		final FortifyCurlProcessor processor = newFortifyCurlProcessor(parameters);
		final String url = StringUtils.appendIfMissing(parameters.get(PARAMETER_URL), "/") + "api/v1/userSession/info";
		final CurlRequest request = new CurlRequest("POST", url, "{}", "Accept: application/json");
		request.setSaveResponse(true);
		processor.process(request);
		processor.close();
		final String content = ObjectUtils.defaultIfNull(request.getResponse(), "{}");
		final Map<String, ?> data = MapUtils
				.emptyIfNull((Map<String, ?>) objectMapper.readValue(content, Map.class).get("data"));
		return (String) data.get("webappVersion");
	}

	@Override
	public boolean checkStatus(final Map<String, String> parameters) throws Exception {
		return StringUtils.isNotEmpty(this.getVersion(parameters));
	}

	@Override
	public SubscriptionStatusWithData checkSubscriptionStatus(final Map<String, String> parameters) throws Exception {
		final SubscriptionStatusWithData nodeStatusWithData = new SubscriptionStatusWithData();
		nodeStatusWithData.put("project", validateProject(parameters));
		return nodeStatusWithData;
	}

	/**
	 * Cache the API token.
	 *
	 * @param url       Fortify URL.
	 * @param user      Access user.
	 * @param password  Access password.
	 * @param processor The related processor where the fortify token will be
	 *                  attached to.
	 * @param force     When <code>true</code>, the token will be regenerated.
	 * @return The security token.
	 *
	 */
	protected String authenticate(final String url, final String user, final String password,
			final FortifyCurlProcessor processor, final boolean force) {
		final String cacheToken = url + DigestUtils.sha256Hex("##" + user + "/" + password);
		if (force) {
			// Replace the token
			final String token = getFortifyToken(url, user, password, processor);
			cacheManager.getCache("curl-tokens").put(cacheToken, token);
			return token;
		}
		return curlCacheToken.getTokenCache(FortifyProject.class, cacheToken,
				k -> getFortifyToken(url, user, password, processor), 1,
				() -> new ValidationJsonException(PARAMETER_URL, "fortify-login"));
	}

	/**
	 * Prepare an authenticated connection to Fortify
	 *
	 * @param parameters The subscription parameters.
	 * @param processor  The related processor where the fortify token will be
	 *                   attached to.
	 * @param force      When <code>true</code>, the cache is ignored.
	 */
	protected void authenticate(final Map<String, String> parameters, final FortifyCurlProcessor processor,
			final boolean force) {
		// Compute the fortify token and store it in the processor
		processor.setFortifyToken(authenticate(parameters.get(PARAMETER_URL), parameters.get(PARAMETER_USER),
				StringUtils.trimToEmpty(parameters.get(PARAMETER_PASSWORD)), processor, force));
	}

	private String getFortifyToken(final String url, final String user, final String password,
			final FortifyCurlProcessor processor) {
		// Use the preempted authentication processor
		processor.setFortifyToken(null);
		final CurlRequest request = new CurlRequest("GET", StringUtils.appendIfMissing(url, "/") + API_TOKEN, null,
				"Accept:application/json", HttpHeaders.AUTHORIZATION + ":Basic "
						+ BASE64_CODEC.encodeToString((user + ':' + password).getBytes(StandardCharsets.UTF_8)));
		request.setSaveResponse(true);
		if (!processor.process(request)) {
			return null;
		}

		// Get the token.
		final Pattern pattern = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"");
		final Matcher matcher = pattern.matcher(request.getResponse());
		if (!matcher.find()) {
			// Something goes wrong
			return null;
		}
		return matcher.group(1);
	}

	private FortifyCurlProcessor newFortifyCurlProcessor(final Map<String, String> parameters) {
		FortifyCurlProcessor processor = new FortifyCurlProcessor(r -> {
			if (r.getStatus() == HttpStatus.SC_UNAUTHORIZED) {
				// Authorization failed, expired token, retry once
				authenticate(parameters, (FortifyCurlProcessor) r.getProcessor(), true);
				return true;
			}
			return false;
		});
		// Check the user can log-in to Fortify
		authenticate(parameters, processor, false);
		return processor;
	}

	/**
	 * Validate the project configuration.
	 *
	 * @param parameters The project parameters.
	 * @return <code>true</code> if the project exists.
	 * @throws IOException When Fortify JSON content cannot be parsed.
	 */
	protected FortifyProject validateProject(final Map<String, String> parameters) throws IOException {
		final FortifyCurlProcessor processor = newFortifyCurlProcessor(parameters);
		try {
			// Check the project exists and get the name
			@SuppressWarnings("unchecked")
			final Map<String, Object> projectMap = MapUtils
					.emptyIfNull((Map<String, Object>) getFortifyResource(parameters,
							API_PROJECTS + parameters.get(PARAMETER_KEY) + "?fields=id,name", processor));
			if (projectMap.isEmpty()) {
				// Project does not exist
				throw new ValidationJsonException(PARAMETER_KEY, "fortify-project");
			}
			final FortifyProject project = toProject(projectMap);

			// Check the projectVersion is within this project
			final String version = parameters.get(PARAMETER_VERSION);
			@SuppressWarnings("unchecked")
			final List<Map<String, Object>> versions = (List<Map<String, Object>>) getFortifyResource(parameters,
					API_PROJECTS + parameters.get(PARAMETER_KEY) + "/versions?fields=id,name", processor);
			project.setVersion(versions.stream().filter(map -> map.get("id").toString().equals(version)).findFirst()
					.orElseThrow(() -> new ValidationJsonException(PARAMETER_VERSION, "fortify-version")).get("name")
					.toString());

			// Get the project versions measures
			@SuppressWarnings("unchecked")
			final List<Map<String, Object>> measures = (List<Map<String, Object>>) getFortifyResource(parameters,
					API_PROJECT_VERSIONS + version + "/performanceIndicatorHistories", processor);
			measures.forEach(map -> project.getMeasures().put(map.get("id").toString(), map.get("value").toString()));
			return project;
		} finally {
			processor.close();
		}

	}

	@Override
	public void link(final int subscription) throws Exception {
		final Map<String, String> parameters = subscriptionResource.getParameters(subscription);

		// Validate the project key
		validateProject(parameters);
	}

	/**
	 * Find the spaces matching to the given criteria.Look into space key, and space
	 * name.
	 *
	 * @param criteria the search criteria.
	 * @param node     the node to be tested with given parameters.
	 * @return project name.
	 * @throws IOException When Fortify JSON content cannot be parsed.
	 */
	@GET
	@Path("{node}/{criteria}")
	@Consumes(MediaType.APPLICATION_JSON)
	public List<FortifyProject> findAllByName(@PathParam("node") final String node,
			@PathParam("criteria") final String criteria) throws IOException {
		return inMemoryPagination
				.newPage(findAll(node, "api/v1/projects?fields=id,name", criteria), PageRequest.of(0, 10)).getContent();
	}

	/**
	 * Find all the versions of a project.
	 *
	 * @param node     the node to be tested with given parameters.
	 * @param project  the project identifier
	 * @param criteria the search criteria.
	 * @return project name.
	 * @throws IOException When Fortify JSON content cannot be parsed.
	 */
	@GET
	@Path("versions/{node}/{project}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Collection<FortifyProject> findProjectVersions(@PathParam("node") final String node,
			@PathParam("project") final String project, @PathParam("criteria") final String criteria)
			throws IOException {
		return findAll(node, API_PROJECTS + project + "/versions?fields=id,name", StringUtils.defaultString(criteria));
	}

	/**
	 * Call a Fortify REST service to fetch items by their name.<br>
	 * NOTE : process manager will be shut down.
	 *
	 * @param node     node to query.
	 * @param url      query URL.
	 * @param criteria Optional name to match.
	 * @return Projects matching to the given criteria.
	 */
	private Collection<FortifyProject> findAll(final String node, final String url, final String criteria)
			throws IOException {
		// Check the user can log in to Fortify
		final Collection<Map<String, Object>> data = getFortifyResource(this.pvResource.getNodeParameters(node), url);
		final Format format = new NormalizeFormat();
		final String formatCriteria = format.format(StringUtils.trimToEmpty(criteria));

		// Filter by criteria on the project name
		final Map<Integer, FortifyProject> result = new TreeMap<>();
		data.stream().filter(item -> (format.format(item.get("name"))).contains(formatCriteria)).forEach(item -> {
			final FortifyProject entry = toProject(item);
			result.put(entry.getId(), entry);
		});
		return result.values();
	}

	/**
	 * Create an authenticated request and return the data. The created processor is
	 * entirely managed : opened and closed.
	 */
	@SuppressWarnings("unchecked")
	private Collection<Map<String, Object>> getFortifyResource(final Map<String, String> parameters,
			final String resource) throws IOException {
		final FortifyCurlProcessor processor = newFortifyCurlProcessor(parameters);
		Collection<Map<String, Object>> result = CollectionUtils
				.emptyIfNull((List<Map<String, Object>>) getFortifyResource(parameters, resource, processor));
		processor.close();
		return result;
	}

	/**
	 * Fetch given node from parameters and given URL, and return the JSON object.
	 */
	private Object getFortifyResource(final Map<String, String> parameters, final String resource,
			final FortifyCurlProcessor processor) throws IOException {
		final String url = StringUtils.appendIfMissing(parameters.get(PARAMETER_URL), "/") + resource;
		final CurlRequest request = new CurlRequest("GET", url, null, "Accept: application/json");
		request.setSaveResponse(true);
		processor.process(request);

		// Parse the JSON response
		final String content = ObjectUtils.defaultIfNull(request.getResponse(), "{}");
		return objectMapper.readValue(content, Map.class).get("data");
	}

	/**
	 * Map raw Fortify values to a bean
	 */
	private FortifyProject toProject(final Map<String, Object> spaceRaw) {
		final FortifyProject space = new FortifyProject();
		space.setId((Integer) spaceRaw.get("id"));
		space.setName((String) spaceRaw.get("name"));
		return space;
	}

}
