package org.jaaslounge.ldap;

import java.security.PrivilegedAction;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

public class LdapConnection {
    public static final int DEFAULT_TIMEOUT = 600000;

    private static LdapConnection instance;

    private int timeout = DEFAULT_TIMEOUT;
    private String providerUrl;

    private Subject subject;
    private DirContext context;
    private Thread closing;

    private LdapConnection() {}

    public static LdapConnection getInstance() {
        if(instance == null)
            instance = new LdapConnection();
        return instance;
    }

    public void setProviderUrl(String providerUrl) {
        this.providerUrl = providerUrl;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
        reset();
    }
    
    public DirContext getContext() {
        return context;
    }

    public void addToEnvironnement(String propName, Object propVal) throws NamingException {
        ensureConnected();
        context.addToEnvironment(propName, propVal);
    }

    public void reset() {
        if(context != null) {
            try {
                context.close();
            } catch(NamingException e) {
                // Can't do more
            } finally {
                context = null;
            }
        }
    }

    public NamingEnumeration<SearchResult> search(String base, String filter,
            SearchControls controls) {
        NamingEnumeration<SearchResult> result = null;
        try {
            ensureAuthentified();
            result = (NamingEnumeration<SearchResult>)Subject.doAs(subject, new PrivilegedSearch(
                    base, filter, controls));
        } catch(LoginException e) {
            e.printStackTrace();
        }
        return result;
    }

    private void ensureAuthentified() throws LoginException {
        if(subject == null) {
            System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
            LoginContext lc = new LoginContext(System.getProperty("jaaslounge.sso.jaas.config"));
            lc.login();
            subject = lc.getSubject();
        }
    }

    private void ensureConnected() throws NamingException {
        if(context == null) {
            Hashtable<Object, Object> env = new Hashtable<Object, Object>(11);
            env.put("javax.security.auth.useSubjectCredsOnly", "false");
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, providerUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");

            context = new InitialDirContext(env);

            closing = new Closure();
            closing.start();
        }
    }

    private class PrivilegedSearch implements PrivilegedAction<NamingEnumeration<SearchResult>> {
        private String base;
        private String filter;
        private SearchControls controls;

        public PrivilegedSearch(String base, String filter, SearchControls controls) {
            this.base = base;
            this.filter = filter;
            this.controls = controls;
        }

        public NamingEnumeration<SearchResult> run() {
            NamingEnumeration<SearchResult> result = null;
            try {
                synchronized(LdapConnection.this) {
                    ensureConnected();
                    result = context.search(base, filter, controls);
                }
            } catch(NamingException e) {
                e.printStackTrace();
            }
            return result;
        }
    }

    private class Closure extends Thread {
        public void run() {
            try {
                sleep(timeout);
                synchronized(LdapConnection.this) {
                    reset();
                }
            } catch(InterruptedException e) {
                // No need to care
            } finally {

                context = null;
                closing = null;
            }
        }
    };
}