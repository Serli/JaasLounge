package org.jaaslounge.ldap;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import junit.framework.TestCase;

import org.ietf.jgss.GSSException;
import org.junit.Before;
import org.junit.Test;

public class TestLdapConnection extends TestCase {

    private static final String LDAP_PROVIDER_URL = "ldap://testad2003:389";
    private String base;
    private String query;
    private SearchControls searchCtls;
    private KeepAliveLdapConnection connection;

    @Before
    protected void setUp() throws Exception {
        System.out.println();
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

    }

    @Test
    public void testSameConnection() throws GSSException {
        NamingEnumeration<SearchResult> names = null;

        connection = KeepAliveLdapConnection.getConnection(LDAP_PROVIDER_URL, 2000, null);

        try {
            names = connection.search(base, query, searchCtls);
        } catch(NamingException e) {
            fail();
        }
        assertTrue(names.hasMoreElements());

        try {
            names = connection.search(base, query, searchCtls);
        } catch(NamingException e) {
            fail();
        }
        assertTrue(names.hasMoreElements());
    }

    public void testTimeoutConnection() {
        NamingEnumeration<SearchResult> names = null;

        connection = KeepAliveLdapConnection.getConnection(LDAP_PROVIDER_URL, 1000, null);

        try {
            names = connection.search(base, query, searchCtls);
        } catch(NamingException e) {
            fail();
        }
        assertTrue(names.hasMoreElements());

        try {
            Thread.sleep(3000);
        } catch(InterruptedException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }

        try {
            names = connection.search(base, query, searchCtls);
        } catch(NamingException e) {
            fail();
        }
        assertTrue(names.hasMoreElements());
    }

    public void testSeveralConnections() {
        NamingEnumeration<SearchResult> names = null;

        connection = KeepAliveLdapConnection.getConnection(LDAP_PROVIDER_URL, 10, null);

        try {
            names = connection.search(base, query, searchCtls);
        } catch(NamingException e) {
            fail();
        }
        assertTrue(names.hasMoreElements());

        int count = 0;
        while(count < 1000) {
            count++;
            try {
                names = connection.search(base, query, searchCtls);
            } catch(Exception e) {
                fail();
            }
            assertTrue(names.hasMoreElements());
        }
    }

    public void testSimultaneousConnections() {
        connection = KeepAliveLdapConnection.getConnection(LDAP_PROVIDER_URL, 1000, null);
        
        List<Thread> threads = new ArrayList<Thread>();
        int count = 0;
        while(count < 10) {
            count++;

            Thread thread = new Thread(){
                @Override
                public void run() {
                    NamingEnumeration<SearchResult> names = null;
                    int count = 0;
                    while(count < 100) {
                        count++;
                        try {
                            names = connection.search(base, query, searchCtls);
                            assertTrue(names.hasMoreElements());
                        } catch (Exception e) {
                            fail();
                        }
                        assertTrue(names.hasMoreElements());
                    }
                }
            };
            threads.add(thread);
            thread.start();
        }
        
        for(Thread thread : threads) {
            try {
                thread.join();
            } catch(InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
