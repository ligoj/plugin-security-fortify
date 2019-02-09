/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.security.fortify;

import java.util.HashMap;
import java.util.Map;

import org.ligoj.bootstrap.core.NamedBean;

import lombok.Getter;
import lombok.Setter;

/**
 * Fortify project.
 */
@Getter
public class FortifyProject extends NamedBean<Integer> {

	/**
	 * SID
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Original fortify measures.
	 */
	private Map<String, String> measures = new HashMap<>();

	/**
	 * Project version name
	 */
	@Setter
	private String version;
}
