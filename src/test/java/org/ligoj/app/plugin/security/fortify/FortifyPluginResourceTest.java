package org.ligoj.app.plugin.security.fortify;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.transaction.Transactional;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ligoj.app.AbstractServerTest;
import org.ligoj.app.MatcherUtil;
import org.ligoj.app.model.Node;
import org.ligoj.app.model.Parameter;
import org.ligoj.app.model.ParameterValue;
import org.ligoj.app.model.Project;
import org.ligoj.app.model.Subscription;
import org.ligoj.app.plugin.security.SecurityResource;
import org.ligoj.app.resource.node.ParameterValueResource;
import org.ligoj.app.resource.subscription.SubscriptionResource;
import org.ligoj.bootstrap.core.INamableBean;
import org.ligoj.bootstrap.core.validation.ValidationJsonException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import net.sf.ehcache.CacheManager;

/**
 * Test class of {@link FortifyPluginResource}
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:/META-INF/spring/application-context-test.xml")
@Rollback
@Transactional
public class FortifyPluginResourceTest extends AbstractServerTest {
	@Autowired
	private FortifyPluginResource resource;

	@Autowired
	private ParameterValueResource pvResource;

	@Autowired
	private SubscriptionResource subscriptionResource;

	protected int subscription;

	@Before
	public void prepareData() throws IOException {
		// Only with Spring context
		persistEntities("csv",
				new Class[] { Node.class, Parameter.class, Project.class, Subscription.class, ParameterValue.class },
				StandardCharsets.UTF_8.name());
		this.subscription = getSubscription("gStack");

		// Coverage only
		resource.getKey();

		// Invalidate Fortify cache
		CacheManager.getInstance().getCache("curl-tokens").removeAll();
	}

	/**
	 * Return the subscription identifier of the given project. Assumes there is only one
	 * subscription for a service.
	 */
	protected int getSubscription(final String project) {
		return getSubscription(project, SecurityResource.SERVICE_KEY);
	}

	@Test
	public void delete() throws Exception {
		resource.delete(subscription, false);
	}

	@Test
	public void getVersion() throws Exception {
		prepareMockHome();
		prepareMockVersion();
		httpServer.start();

		final String version = resource.getVersion(subscription);
		Assert.assertEquals("4.30.0086", version);
	}

	@Test
	public void getVersionFailed() throws Exception {
		assertConnectionFailed();
		httpServer.start();
		resource.getVersion(subscription);
	}

	@Test
	public void getLastVersion() throws Exception {
		final String lastVersion = resource.getLastVersion();
		Assert.assertNull(lastVersion);
	}

	@Test
	public void link() throws Exception {
		prepareMockHome();
		prepareMockProjectVersions();

		// Invoke create for an already created entity, since for now, there is
		// nothing but validation pour SonarQube
		resource.link(this.subscription);

		// Nothing to validate for now...
	}

	@Test(expected = ValidationJsonException.class)
	public void validateProjectNotFound() throws Exception {
		prepareMockProjectVersions();

		final Map<String, String> parameters = pvResource.getNodeParameters("service:security:fortify:dig");
		parameters.put(FortifyPluginResource.PARAMETER_KEY, "2");
		parameters.put(FortifyPluginResource.PARAMETER_VERSION, "0"); // no
																		// version
																		// with
																		// this
																		// identifier
		resource.validateProject(parameters);
	}

	@Test
	public void validateProject() throws Exception {
		prepareMockProjectVersions();

		final Map<String, String> parameters = pvResource.getNodeParameters("service:security:fortify:dig");
		parameters.put(FortifyPluginResource.PARAMETER_KEY, "2");
		parameters.put(FortifyPluginResource.PARAMETER_VERSION, "4");

		assertProject(resource.validateProject(parameters));
	}

	@Test
	public void checkStatusSubscriptionStatus() throws Exception {
		prepareMockProjectVersions();
		Assert.assertTrue(resource.checkSubscriptionStatus(subscriptionResource.getParametersNoCheck(subscription))
				.getStatus().isUp());
	}

	/**
	 * Project is not found
	 */
	@Test
	public void checkStatusSubscriptionStatusProjectNotFound() throws Exception {
		thrown.expect(ValidationJsonException.class);
		thrown.expect(MatcherUtil.validationMatcher(FortifyPluginResource.PARAMETER_KEY, "fortify-project"));

		prepareMockHome();

		// Find project return an empty list
		httpServer.stubFor(get(urlPathEqualTo("/api/v1/projects/2"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_OK).withBody("{}")));
		httpServer.start();
		Assert.assertFalse(resource.checkSubscriptionStatus(subscriptionResource.getParametersNoCheck(subscription))
				.getStatus().isUp());
	}

	/**
	 * Version is not found
	 */
	@Test
	public void checkStatusSubscriptionStatusVersionNotFound() throws Exception {
		thrown.expect(ValidationJsonException.class);
		thrown.expect(MatcherUtil.validationMatcher(FortifyPluginResource.PARAMETER_VERSION, "fortify-version"));

		prepareMockHome();
		httpServer.stubFor(get(urlPathEqualTo("/api/v1/projects/2")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)
				.withBody(IOUtils.toString(
						new ClassPathResource("mock-server/fortify/fortify-api-projects-detail.json").getInputStream(),
						StandardCharsets.UTF_8))));

		// Find project return an empty list
		httpServer.stubFor(get(urlPathEqualTo("/api/v1/projects/2/versions"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_OK).withBody("{\"data\":[]}")));
		httpServer.start();
		Assert.assertFalse(resource.checkSubscriptionStatus(subscriptionResource.getParametersNoCheck(subscription))
				.getStatus().isUp());
	}

	@Test
	public void checkStatusSubscriptionStatusException() throws Exception {
		assertConnectionFailed();
		httpServer.stubFor(post(urlPathEqualTo("/j_spring_security_check"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_NOT_FOUND)));
		httpServer.start();
		resource.checkSubscriptionStatus(subscriptionResource.getParametersNoCheck(subscription));
	}

	private void prepareMockProjects() throws IOException {
		prepareMockHome();
		// Find all projects
		httpServer.stubFor(get(urlPathEqualTo("/api/v1/projects")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)
				.withBody(IOUtils.toString(
						new ClassPathResource("mock-server/fortify/fortify-api-projects.json").getInputStream(),
						StandardCharsets.UTF_8))));
		httpServer.start();
	}

	private void prepareMockProjectVersions() throws IOException {
		prepareMockHome();
		// Find space
		httpServer.stubFor(get(urlPathEqualTo("/api/v1/projects/2")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)
				.withBody(IOUtils.toString(
						new ClassPathResource("mock-server/fortify/fortify-api-projects-detail.json").getInputStream(),
						StandardCharsets.UTF_8))));
		httpServer.stubFor(get(urlPathEqualTo("/api/v1/projects/2/versions"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_OK).withBody(
						IOUtils.toString(new ClassPathResource("mock-server/fortify/fortify-api-projects-versions.json")
								.getInputStream(), StandardCharsets.UTF_8))));
		httpServer
				.stubFor(get(urlPathEqualTo("/api/v1/projectVersions/4/performanceIndicatorHistories"))
						.willReturn(aResponse().withStatus(HttpStatus.SC_OK)
								.withBody(IOUtils.toString(new ClassPathResource(
										"mock-server/fortify/fortify-api-projects-indicators.json").getInputStream(),
										StandardCharsets.UTF_8))));
		httpServer.start();
	}

	@Test
	public void checkStatus() throws Exception {
		prepareMockProjects();
		prepareMockVersion();
		httpServer.start();
		Assert.assertTrue(resource.checkStatus(subscriptionResource.getParametersNoCheck(subscription)));
	}

	@Test
	public void checkStatusNoConnection() throws Exception {
		assertConnectionFailed();
		httpServer.start();
		Assert.assertFalse(resource.checkStatus(subscriptionResource.getParametersNoCheck(subscription)));
	}

	@Test
	public void checkStatusNotAuthentication() throws Exception {
		assertConnectionFailed();
		httpServer.stubFor(
				post(urlPathEqualTo("/j_spring_security_check")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)));
		httpServer.start();
		Assert.assertFalse(resource.checkStatus(subscriptionResource.getParametersNoCheck(subscription)));
	}

	@Test
	public void checkStatusNotAuthenticationNotCorrectLocation() throws Exception {
		assertConnectionFailed();
		httpServer.stubFor(post(urlPathEqualTo("/j_spring_security_check"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_MOVED_TEMPORARILY).withHeader("location", "any.jsp")));
		httpServer.start();
		Assert.assertFalse(resource.checkStatus(subscriptionResource.getParametersNoCheck(subscription)));
	}

	@Test
	public void checkStatusNotAuthenticationNoLocation() throws Exception {
		assertConnectionFailed();
		httpServer.stubFor(post(urlPathEqualTo("/j_spring_security_check"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_MOVED_TEMPORARILY)));
		httpServer.start();
		Assert.assertFalse(resource.checkStatus(subscriptionResource.getParametersNoCheck(subscription)));
	}

	@Test
	public void checkStatusNoToken() throws Exception {
		assertConnectionFailed();
		httpServer.stubFor(post(urlPathEqualTo("/j_spring_security_check")).willReturn(
				aResponse().withStatus(HttpStatus.SC_MOVED_TEMPORARILY).withHeader("location", "index.jsp")));
		httpServer.stubFor(
				get(urlPathEqualTo("/flex/index.jsp")).willReturn(aResponse().withStatus(HttpStatus.SC_NOT_FOUND)));
		httpServer.start();
		Assert.assertFalse(resource.checkStatus(subscriptionResource.getParametersNoCheck(subscription)));
	}

	@Test
	public void checkStatusNoTokenContent() throws Exception {
		assertConnectionFailed();
		httpServer.stubFor(post(urlPathEqualTo("/j_spring_security_check")).willReturn(
				aResponse().withStatus(HttpStatus.SC_MOVED_TEMPORARILY).withHeader("location", "index.jsp")));
		httpServer.stubFor(get(urlPathEqualTo("/flex/index.jsp"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_OK).withBody("any")));
		httpServer.start();
		Assert.assertFalse(resource.checkStatus(subscriptionResource.getParametersNoCheck(subscription)));
	}

	private void prepareMockVersion() throws IOException {
		// Version
		httpServer.stubFor(post(urlPathEqualTo("/api/v1/userSession/info")).willReturn(aResponse()
				.withStatus(HttpStatus.SC_OK)
				.withBody(IOUtils.toString(
						new ClassPathResource("mock-server/fortify/fortify-api-userSession-info.json").getInputStream(),
						StandardCharsets.UTF_8))));
	}

	private void assertConnectionFailed() {
		thrown.expect(ValidationJsonException.class);
		thrown.expect(MatcherUtil.validationMatcher(FortifyPluginResource.PARAMETER_URL, "fortify-login"));
	}

	private void prepareMockHome() throws IOException {
		httpServer.stubFor(post(urlPathEqualTo("/j_spring_security_check")).willReturn(
				aResponse().withStatus(HttpStatus.SC_MOVED_TEMPORARILY).withHeader("location", "index.jsp")));
		httpServer.stubFor(get(urlPathEqualTo("/flex/index.jsp")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)
				.withBody(IOUtils.toString(new ClassPathResource("mock-server/fortify/index.jsp").getInputStream(),
						StandardCharsets.UTF_8))));

	}

	@Test
	public void checkStatusNotAccess() throws Exception {
		assertConnectionFailed();
		httpServer.stubFor(post(urlPathEqualTo("/j_spring_security_check"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_NOT_FOUND)));
		httpServer.start();
		resource.checkStatus(subscriptionResource.getParametersNoCheck(subscription));
	}

	@Test
	public void findAllByName() throws Exception {
		prepareMockProjects();

		final List<FortifyProject> projects = resource.findAllByName("service:security:fortify:dig", "nosvent");
		Assert.assertEquals(1, projects.size());
		checkProject(projects.get(0));
	}

	@Test
	public void findProjectVersions() throws Exception {
		prepareMockProjectVersions();

		final Collection<FortifyProject> versions = resource.findProjectVersions("service:security:fortify:dig", "2",
				StringUtils.EMPTY);
		Assert.assertEquals(1, versions.size());
		Assert.assertEquals(4, versions.stream().findFirst().get().getId().intValue());
		Assert.assertEquals("1.0", versions.stream().findFirst().get().getName());
	}

	private void assertProject(final FortifyProject project) {
		Assert.assertEquals(2, project.getId().intValue());
		Assert.assertEquals("gfi-saas", project.getName());
		Assert.assertEquals("1.0", project.getVersion());

		Assert.assertEquals("1160.0", project.getMeasures().get("TotalRemediationEffort"));
		Assert.assertEquals("208.0", project.getMeasures().get("Issues"));
		Assert.assertEquals("1.35", project.getMeasures().get("VDEN"));
	}

	@Test
	public void findAllByNameInvalidConnection() throws Exception {
		assertConnectionFailed();
		httpServer.stubFor(post(urlPathEqualTo("/j_spring_security_check"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_NOT_FOUND)));
		httpServer.start();
		resource.findAllByName("service:security:fortify:dig", "nosvent");
	}

	@Test
	public void findAllByNameInvalidUrl() throws Exception {
		assertConnectionFailed();
		httpServer.stubFor(post(urlPathEqualTo("/j_spring_security_check"))
				.willReturn(aResponse().withStatus(HttpStatus.SC_NOT_FOUND)));
		httpServer.start();
		resource.findAllByName("service:security:fortify:dig", "nosvent");
	}

	private void checkProject(final INamableBean<Integer> space) {
		Assert.assertEquals(8, space.getId().intValue());
		Assert.assertEquals("orange-nosventes", space.getName());
	}
}
