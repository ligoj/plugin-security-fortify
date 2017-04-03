package org.ligoj.app.plugin.security.fortify;

import org.ligoj.app.resource.plugin.CurlProcessor;
import org.ligoj.app.resource.plugin.CurlRequest;
import org.ligoj.app.resource.plugin.HttpResponseCallback;

import lombok.Setter;

/**
 * Forty curl processor handling CSRF token.
 */
@Setter
public class FortifyCurlProcessor extends CurlProcessor {

	/**
	 * Special callback for Fortify login check.
	 */
	public static final HttpResponseCallback LOGIN_CALLBACK = new FortifyLoginHttpResponseCallback();

	/**
	 * Token used to authenticate request
	 */
	private String fortifyToken;

	@Override
	protected boolean process(final CurlRequest request) {
		if (fortifyToken != null) {
			request.getHeaders().put("Authorization", "FortifyToken " + this.fortifyToken);
		}
		return super.process(request);
	}

}
