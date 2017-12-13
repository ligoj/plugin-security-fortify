package org.ligoj.app.plugin.security.fortify;

import java.io.IOException;
import java.text.Format;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.ligoj.app.api.SubscriptionStatusWithData;
import org.ligoj.app.plugin.security.SecurityResource;
import org.ligoj.app.plugin.security.SecurityServicePlugin;
import org.ligoj.app.resource.NormalizeFormat;
import org.ligoj.app.resource.plugin.AbstractToolPluginResource;
import org.ligoj.app.resource.plugin.CurlCacheToken;
import org.ligoj.app.resource.plugin.CurlRequest;
import org.ligoj.bootstrap.core.json.InMemoryPagination;
import org.ligoj.bootstrap.core.validation.ValidationJsonException;
import org.springframework.beans.factory.annotation.Autowired;
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

	@Override
	public String getKey() {
		return KEY;
	}

	@SuppressWarnings("unchecked")
	@Override
	public String getVersion(final Map<String, String> parameters) throws Exception {
		final FortifyCurlProcessor processor = new FortifyCurlProcessor();
		// Check the user can log-in to Fortify
		authenticate(parameters, processor);

		final String url = StringUtils.appendIfMissing(parameters.get(PARAMETER_URL), "/") + "api/v1/userSession/info";
		final CurlRequest request = new CurlRequest("POST", url, null, "Accept: application/json");
		request.setSaveResponse(true);
		processor.process(request);
		final String content = ObjectUtils.defaultIfNull(request.getResponse(), "{}");
		final ObjectMapper mapper = new ObjectMapper();
		final Map<String, ?> data = MapUtils
				.emptyIfNull((Map<String, ?>) mapper.readValue(content, Map.class).get("data"));
		final String version = (String) data.get("webappVersion");
		processor.close();
		return version;
	}

	@Override
	public boolean checkStatus(final Map<String, String> parameters) throws Exception {
		return StringUtils.isNotEmpty(this.getVersion(parameters));
	}

	@Override
	public SubscriptionStatusWithData checkSubscriptionStatus(final Map<String, String> parameters)
			throws Exception {
		final SubscriptionStatusWithData nodeStatusWithData = new SubscriptionStatusWithData();
		nodeStatusWithData.put("project", validateProject(parameters));
		return nodeStatusWithData;
	}

	/**
	 * Cache the API token.
	 */
	protected String authenticate(final String url, final String authentication, final FortifyCurlProcessor processor) {
		return curlCacheToken.getTokenCache(FortifyProject.class, url + "##" + authentication, k -> {

			// Authentication request
			final List<CurlRequest> requests = new ArrayList<>();
			requests.add(new CurlRequest(HttpMethod.POST, url + "/j_spring_security_check", authentication + "&hash=",
					FortifyCurlProcessor.LOGIN_CALLBACK,
					"Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));

			// used to obtain the Fortify token into the page's content.
			final CurlRequest requestIndex = new CurlRequest(HttpMethod.GET,
					StringUtils.appendIfMissing(url, "/") + "flex/index.jsp", "",
					"Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
			requestIndex.setSaveResponse(true);

			requests.add(requestIndex);
			if (!processor.process(requests)) {
				return null;
			}

			// try to obtain the fortify's token.
			final String content = ObjectUtils.defaultIfNull(requestIndex.getResponse(), "");
			final Pattern pattern = Pattern.compile("FortifyToken ([\\w]+)");
			final Matcher matcher = pattern.matcher(content);
			if (!matcher.find()) {
				return null;
			}
			return matcher.group(1);
		}, 1, () -> new ValidationJsonException(PARAMETER_URL, "fortify-login"));
	}

	/**
	 * Validate the project configuration.
	 * 
	 * @param parameters
	 *            the project parameters.
	 * @return true if the project exists.
	 */
	protected FortifyProject validateProject(final Map<String, String> parameters) throws IOException {
		final FortifyCurlProcessor processor = new FortifyCurlProcessor();
		try {
			// Authenticate
			authenticate(parameters, processor);

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
	 * Find the spaces matching to the given criteria.Look into space key, and
	 * space name.
	 * 
	 * @param criteria
	 *            the search criteria.
	 * @param node
	 *            the node to be tested with given parameters.
	 * @return project name.
	 */
	@GET
	@Path("{node}/{criteria}")
	@Consumes(MediaType.APPLICATION_JSON)
	public List<FortifyProject> findAllByName(@PathParam("node") final String node,
			@PathParam("criteria") final String criteria) throws IOException {
		return inMemoryPagination
				.newPage(findAll(node, "api/v1/projects?fields=id,name", criteria), PageRequest.of(0, 10))
				.getContent();
	}

	/**
	 * Find all the versions of a project.
	 * 
	 * @param node
	 *            the node to be tested with given parameters.
	 * @param project
	 *            the project identifier
	 * @param criteria
	 *            the search criteria.
	 * @return project name.
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
	 * @param node
	 *            node to query.
	 * @param url
	 *            query URL.
	 * @param criteria
	 *            Optional name to match.
	 * @return Projects matching to the given criteria.
	 */
	private Collection<FortifyProject> findAll(final String node, final String url, final String criteria)
			throws IOException {
		// Check the user can log-in to Fortify
		final Collection<Map<String, Object>> data = getFortifyResource(this.pvResource.getNodeParameters(node),
				url);
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
	 * Create an authenticated request and return the data. The created
	 * processor is entirely managed : opened and closed.
	 */
	@SuppressWarnings("unchecked")
	private Collection<Map<String, Object>> getFortifyResource(final Map<String, String> parameters,
			final String resource) throws IOException {
		final FortifyCurlProcessor processor = new FortifyCurlProcessor();
		try {
			authenticate(parameters, processor);
			return CollectionUtils
					.emptyIfNull((List<Map<String, Object>>) getFortifyResource(parameters, resource, processor));
		} finally {
			processor.close();
		}
	}

	/**
	 * Fetch given node from parameters and given URL, and return the JSON
	 * object.
	 */
	private Object getFortifyResource(final Map<String, String> parameters, final String resource,
			final FortifyCurlProcessor processor) throws IOException {

		final String url = StringUtils.appendIfMissing(parameters.get(PARAMETER_URL), "/") + resource;
		final CurlRequest request = new CurlRequest("GET", url, null);
		request.setSaveResponse(true);
		processor.process(request);

		// Parse the JSON response
		final String content = ObjectUtils.defaultIfNull(request.getResponse(), "{}");
		final ObjectMapper mapper = new ObjectMapper();
		return mapper.readValue(content, Map.class).get("data");
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

	/**
	 * Prepare an authenticated connection to Fortify
	 */
	protected void authenticate(final Map<String, String> parameters, final FortifyCurlProcessor processor) {
		// Compute the fortify token and store it in the processor
		processor.setFortifyToken(
				authenticate(parameters.get(PARAMETER_URL), "j_username=" + parameters.get(PARAMETER_USER)
						+ "&j_password=" + StringUtils.trimToEmpty(parameters.get(PARAMETER_PASSWORD)), processor));
	}

}
