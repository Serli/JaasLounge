package org.jaaslounge;

import java.net.URL;
import java.security.Principal;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

public class Test {

	public static void main(String[] args) throws LoginException {

        URL url = Test.class.getClassLoader().getResource("login.conf");
        System.setProperty("java.security.auth.login.config", url.toExternalForm());
        LoginContext loginContext = new LoginContext("com.sun.security.jgss.accept");
		loginContext.login();
        Subject serviceSubject = loginContext.getSubject();
        
        System.out.println("Service principals found: " + serviceSubject.getPrincipals().size());
		for(Principal servicePrincipal:serviceSubject.getPrincipals())
			System.out.println("Service principal name: " + servicePrincipal.getName());
		
        System.out.println("Service public credentials found: " + serviceSubject.getPublicCredentials().size());
		for(Object serviceCredential:serviceSubject.getPublicCredentials())
			System.out.println("Service credential class: " + serviceCredential.getClass().getName());

        System.out.println("Service private credentials found: " + serviceSubject.getPrivateCredentials().size());
		for(Object serviceCredential:serviceSubject.getPrivateCredentials())
			System.out.println("Service credential class: " + serviceCredential.getClass().getName());
		
		loginContext.logout();
	}

}
