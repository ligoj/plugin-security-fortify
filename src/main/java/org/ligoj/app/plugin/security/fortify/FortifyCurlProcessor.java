/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.security.fortify;

import java.util.function.Function;

import org.ligoj.bootstrap.core.curl.CurlProcessor;
import org.ligoj.bootstrap.core.curl.CurlRequest;

import lombok.Getter;
import lombok.Setter;

/**
 * Forty curl processor handling CSRF token.
 */
public class FortifyCurlProcessor extends CurlProcessor {

	/**
	 * Initialization of replay.
	 * 
	 * @param authenticate Authenticate function.
	 */
	public FortifyCurlProcessor(final Function<CurlRequest, Boolean> authenticate) {
		super.replay = authenticate;
	}

	/**
	 * Token used to authenticate request
	 */
	@Setter
	@Getter
	private String fortifyToken;

	@Override
	protected boolean process(final CurlRequest request) {
		if (fortifyToken != null) {
			request.getHeaders().put("Authorization", "FortifyToken " + getFortifyToken());
		}
		return super.process(request);
	}

}
