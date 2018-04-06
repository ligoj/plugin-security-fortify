package org.ligoj.app.plugin.security.fortify;

import java.util.function.Function;

import org.ligoj.app.resource.plugin.CurlProcessor;
import org.ligoj.app.resource.plugin.CurlRequest;

import lombok.Getter;
import lombok.Setter;

/**
 * Forty curl processor handling CSRF token.
 */
public class FortifyCurlProcessor extends CurlProcessor {

	public FortifyCurlProcessor(Function<CurlRequest, Boolean> authenticate) {
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
			request.getHeaders().put("Authorization", "FortifyToken " + this.fortifyToken);
		}
		return super.process(request);
	}

}
