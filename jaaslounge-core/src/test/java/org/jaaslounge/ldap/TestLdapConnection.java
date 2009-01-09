package org.jaaslounge.ldap;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import junit.framework.TestCase;

import org.ietf.jgss.GSSException;
import org.junit.Before;
import org.junit.Test;

public class TestLdapConnection extends TestCase {

    private String base;
    private String query;
    private SearchControls searchCtls;
    private LdapConnection connection;

    @Before
    protected void setUp() throws Exception {
        String path = this.getClass().getClassLoader().getResource("krb5.login.conf").toExternalForm();
        System.setProperty("java.security.auth.login.config", path.replace("%20", " "));
        System.setProperty("java.security.krb5.realm", "EX2003.COM"); 
        System.setProperty("java.security.krb5.kdc", "testad2003.ex2003.com"); 
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

        base = "DC=ex2003,DC=com";
        query = "(objectClass=person)";
        searchCtls = new SearchControls();
        searchCtls.setReturningAttributes(new String[]{"sAMAccountName"});
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        connection = LdapConnection.getInstance();
        connection.setProviderUrl("ldap://testad2003:389");
        connection.addToEnvironnement(Context.SECURITY_AUTHENTICATION, "GSSAPI");
    }

    @Test
    public void testSameConnection() throws GSSException {
        NamingEnumeration<SearchResult> names;

        connection.setTimeout(600000);

        names = connection.search(base, query, searchCtls);
        DirContext context1 = connection.getContext();
        assertTrue(names.hasMoreElements());

        names = connection.search(base, query, searchCtls);
        DirContext context2 = connection.getContext();
        assertTrue(names.hasMoreElements());

        assertSame(context1, context2);
    }

    public void testTimeoutConnection() {
        NamingEnumeration<SearchResult> names;

        connection.setTimeout(1000);

        names = connection.search(base, query, searchCtls);
        DirContext context1 = connection.getContext();
        assertTrue(names.hasMoreElements());

        try {
            Thread.sleep(3000);
        } catch(InterruptedException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }

        names = connection.search(base, query, searchCtls);
        DirContext context2 = connection.getContext();
        assertTrue(names.hasMoreElements());

        assertNotSame(context1, context2);
    }

    public void testSeveralConnection() {
        NamingEnumeration<SearchResult> names;

        connection.setTimeout(10);

        names = connection.search(base, query, searchCtls);
        DirContext context1 = connection.getContext();
        assertTrue(names.hasMoreElements());

        int count = 0;
        while(count < 10) {
            count++;
            names = connection.search(base, query, searchCtls);
            assertTrue(names.hasMoreElements());
        }
        DirContext context2 = connection.getContext();

        assertNotSame(context1, context2);
    }
}
