package org.jaaslounge;

import java.security.Principal;

/**
 * Décorateur de Principal pour permettre de modifier 
 * selon la configuration choisie.
 */
public class ConfigurablePrincipal implements Principal {

	public static final int PRINCIPAL_NAME_UNCHANGED = 0;
	public static final int PRINCIPAL_NAME_SAMNAME = 1;
	public static final int PRINCIPAL_NAME_NTLMNAME = 2;
	public static final int PRINCIPAL_NAME_ADNAME = 3;

	private Principal original;
	private String domain;
	private int type;
	
	public ConfigurablePrincipal(Principal aOriginal, String aDomain, int aType) {
		original = aOriginal;
		domain = aDomain;
		type = aType;
	}
	
	public boolean equals(Object another) {
		return original.equals(another);
	}

	public String toString() {
		return original.toString();
	}

	public int hashCode() {
		return original.hashCode();
	}
	
	public String getName() {
		String oname = original.getName();
		String name = oname;
		String dname = domain;
		
		if (type != PRINCIPAL_NAME_UNCHANGED) {
			int index = oname.indexOf('\\');
			if (index == -1) index = oname.indexOf('/');
			if (index != -1) {
				dname = oname.substring(0, index);
				name = oname.substring(index + 1);
			} else {
				index = oname.indexOf('@');
				if (index != -1) {
					dname = oname.substring(index + 1);
					name = oname.substring(0, index);
				}
			}
			
			switch (type) {				
			case PRINCIPAL_NAME_NTLMNAME :
				return dname + "\\" + name;
				
			case PRINCIPAL_NAME_ADNAME :
				return name + "@" + dname;
			}				
		}			
		return name;
	}		
}
