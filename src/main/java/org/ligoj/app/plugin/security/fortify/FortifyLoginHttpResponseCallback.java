package org.ligoj.app.plugin.security.fortify;

import org.ligoj.app.resource.plugin.OnlyRedirectHttpResponseCallback;

/**
 * Fortify login response handler.
 */
public class FortifyLoginHttpResponseCallback extends OnlyRedirectHttpResponseCallback {

	@Override
	protected boolean acceptLocation(final String location) {
		return super.acceptLocation(location) && location.matches(".*index.jsp(;jsessionid=.+)?$");
	}
}
