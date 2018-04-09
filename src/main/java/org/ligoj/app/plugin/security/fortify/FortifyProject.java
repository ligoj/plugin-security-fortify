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
@Setter
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
	private String version;
}
