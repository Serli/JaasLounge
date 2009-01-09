package org.jaaslounge.ldap;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class LdapSidConverter {

	private String directoryUrl;
	private String directoryBase;
    private String directoryTimeout;

	public LdapSidConverter(String directoryUrl, String directoryBase, String directoryTimeout) {
		this.directoryUrl = directoryUrl;
        this.directoryBase = directoryBase;
        this.directoryTimeout = directoryTimeout;
	}

	public List<String> getGroupNames(List<String> sids) throws NamingException {
		List<String> names = null;

		LdapConnection ldapConnection = LdapConnection.getInstance();
		
		int timeout;
		try{
		    timeout = Integer.parseInt(directoryTimeout);
		}catch(Exception e){
		    timeout = LdapConnection.DEFAULT_TIMEOUT;
		}
		
		ldapConnection.setTimeout(timeout);
        ldapConnection.setProviderUrl(directoryUrl);
		ldapConnection.addToEnvironnement("java.naming.ldap.attributes.binary", "objectSid");

		SearchControls searchCtls = new SearchControls();
		searchCtls.setReturningAttributes(new String[] { "sAMAccountName" });
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		StringBuilder filterBuilder = new StringBuilder();
		filterBuilder.append("(&(objectClass=group)(|");
		for (String sid : sids)
			filterBuilder.append("(objectSid=" + sid + ")");
		filterBuilder.append("))");

		names = new ArrayList<String>();
		NamingEnumeration<SearchResult> answer = ldapConnection.search(
				directoryBase, filterBuilder.toString(), searchCtls);
		while (answer.hasMoreElements()) {
			Attributes resultAttrs = ((SearchResult) answer.nextElement()).getAttributes();
			if (resultAttrs != null)
				names.add((String) resultAttrs.get("sAMAccountName").get());
		}

		return names;
	}

}
