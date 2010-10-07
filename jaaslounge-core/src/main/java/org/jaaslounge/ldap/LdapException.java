package org.jaaslounge.ldap;

public class LdapException extends Exception {
	private static final long serialVersionUID = 1L;

	private final Throwable cause;

	public LdapException() {
		this(null, null);
	}

	public LdapException(String message) {
		this(message, null);
	}

	public LdapException(Throwable cause) {
		this(null, cause);
	}

	public LdapException(String message, Throwable cause) {
		super(message);
		this.cause = cause;
	}

	public Throwable getCause() {
		return cause;
	}

}
