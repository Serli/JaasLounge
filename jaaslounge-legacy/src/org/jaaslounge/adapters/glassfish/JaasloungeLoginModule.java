/*
 * Created on 16 févr. 2006
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package org.jaaslounge.adapters.glassfish;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.logging.Level;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.jaaslounge.AbstractLoginModule;

import com.sun.enterprise.security.auth.login.PasswordLoginModule;

/**
 * @author jérôme
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class JaasloungeLoginModule extends PasswordLoginModule {
	
	
	
	private JaasloungeRealm _jaasloungeRealm = null;
	private String _jaasloungeContextName = null;
	private LoginContext _jaasloungeLoginContext = null;
	
	private String _jaasloungeModule=null;
	
	/**
	 * Performs authentication for the current user.
	 *
	 */
	protected void authenticate() throws LoginException        
	{
		_logger.log(Level.CONFIG,"JaasloungeLoginModule.authenticateUser");
		if (!(_currentRealm instanceof JaasloungeRealm)) {            
			throw new LoginException("not a JaasloungeRealm");
		}
		_jaasloungeRealm = (JaasloungeRealm)_currentRealm;
		
		_jaasloungeModule = _currentRealm.getProperty("jaaslounge-module");
		
		
		AbstractLoginModule lm=null;
		
		try {
			lm = (AbstractLoginModule)Class.forName(_jaasloungeModule).newInstance();
		} catch (Exception e) {
	    	String arrayString = "";
	    	for (int i = 0; i < e.getStackTrace().length; i++) {
	    		if (i > 0) { arrayString += " / "; }
	    		arrayString += e.getStackTrace()[i].toString(); 
	    	}
			throw new LoginException("unable to instanciate login module : "+ e.getClass().getName() +" : "+ arrayString);
		}
		Subject subject = new Subject();
		
		CallbackHandler cbh = new CallbackHandler() {		        	
			public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
				
				Callback[] mono=new Callback[1];
				for (int i = 0; i < callbacks.length; i++) {
					mono[0]=callbacks[i];
					if (mono[0] instanceof NameCallback) {
						((NameCallback)mono[0]).setName(_username);
					} else if (mono[0] instanceof PasswordCallback) {
						((PasswordCallback)mono[0]).setPassword(_password.toCharArray());
						
					} 
				}
			}
		};
		
		_logger.log(Level.CONFIG,"JaasloungeLoginModule options : "+_jaasloungeRealm.getOptions());
		lm.initialize(subject, cbh, new HashMap(), _jaasloungeRealm.getOptions() );
		lm.login();
		lm.commit();
		
		
		
		
		
		Collection groups = lm.getUserGroups();
		String[] groupList =(String[]) groups.toArray(new String[groups.size()]);
		 	
		
		
		
		commitAuthentication(_username, _password,	_currentRealm, groupList);
		
		_jaasloungeRealm.setGroupNames(_username, groupList);
		
		
	}
	
	
}
