package org.jaaslounge.adapters.websphere;

/**===============================================================================
* Custom registry for websphere using a jaaslounge loginModule
*===============================================================================
*   The loginModule must have been registered in 'Application Login Configuration'
*   in the Global Security panel of websphere server administration console
*
*   * Custom Properties specific to the jaaslounge module are set at the module 
*     configuration level
*   * Two Custom Properties are to be set at the Custom Registry 
*      configuration level: 
*     - moduleName must contain the name given to the application loginModule
*     - realmName is the name that should be returned by the registry's 
*       getRealm() method
*   * An optional "debug" property might be set to true
*===============================================================================
* This file is based on IBM's FileRegistrySample class
*===============================================================================*/

import java.util.*;
import java.security.cert.X509Certificate;

import javax.security.auth.login.LoginException;
import javax.security.auth.Subject;

import com.ibm.websphere.security.*;
import com.ibm.websphere.security.auth.callback.WSCallbackHandlerImpl;

import org.jaaslounge.GroupPrincipal;

public class JaasloungeRegistry implements UserRegistry {

	private static String _moduleName = null;        
	private static String _realmName = null;
	private static boolean _debug = false;
	private static boolean _connected = false;
	private static String _loggedUserName = null;
	private static javax.security.auth.login.LoginContext _loginContext = null;
	private static javax.security.auth.callback.CallbackHandler _callbackHandler;
	
	private void debug(String string) {
	   if (_debug) System.out.println("["+getClass().getName()+"] " + string);
	}
	
	
	/** Default Constructor **/
	public JaasloungeRegistry() throws java.rmi.RemoteException {
	}
	
	/**
	* Initializes the registry. This method is called when creating the
	* registry.
	*
	* @param     props - The registry-specific properties with which to
	*                    initialize the custom registry
	* @exception CustomRegistryException
	*                    if there is any registry-specific problem
	**/
	public void initialize(java.util.Properties props)
	      throws CustomRegistryException {
	   try {
	       if (props != null) {
	       	_moduleName = props.getProperty("moduleName");
	       	_realmName = props.getProperty("realmName");
	       	if (props.getProperty("debug")!= null
	       			&& "true".equals(props.getProperty("debug")))
	       		_debug = true;
	       }
	
	   } catch(Exception ex) {
	      throw new CustomRegistryException(ex.getMessage(),ex);
	   }
	
	   debug("initialize()");
	   
	   if (_moduleName == null) {
	      throw new CustomRegistryException("'moduleName' custom property has not been set");
	   }
	
	   if (_realmName == null) {
	      throw new CustomRegistryException("'realmName' custom property has not been set");
	   }
	}
	
	/**
	* Checks the password of the user. This method is called to authenticate
	* a user when the user's name and password are given.
	*
	* @param  userSecurityName the name of user
	* @param  password the password of the user
	* @return a valid userSecurityName. Normally this is
	*         the name of same user whose password was checked 
	*         but if the implementation wants to return any other
	*         valid userSecurityName in the registry it can do so
	* @exception CheckPasswordFailedException if userSecurityName/
	*            password combination does not exist 
	*            in the registry
	* @exception CustomRegistryException if there is any registry-
	*            specific problem
	**/
	public String checkPassword(String userSecurityName, String passwd) 
	   throws PasswordCheckFailedException,
	          CustomRegistryException {
		
	   String userName = null;
	   debug("checkPassword(" + userSecurityName + "/***");
	   
	   // get the loginContext
	   try {
	       // create the login context using WebSphere Application Server
	       // callback handler
	       _callbackHandler = new WSCallbackHandlerImpl(userSecurityName, passwd);
	       _loginContext = new javax.security.auth.login.LoginContext(_moduleName, _callbackHandler);
	   } catch (LoginException le) {
	   	throw new PasswordCheckFailedException("JAAS authentication failed in module " 
	   										+ _moduleName + ": Cannot create LoginContext ("
												+ le.getMessage() + ")");
	   }
	   
	   if (_loginContext == null) {
	   	throw new PasswordCheckFailedException("JAAS authentication failed in module " 
					+ _moduleName + ": LoginContext is null!");
	   }
	
	   try {
	       // perform login
	   	_loginContext.login();
	   } catch (LoginException le) {
	       Throwable root_exception = determineCause(le);
	    	throw new PasswordCheckFailedException("JAAS Sample Authentication failed: "
	               + root_exception.getMessage());
	   }
	
	   _connected = true;
	   _loggedUserName = userSecurityName;
		
	   debug("Logged in user: " + _loggedUserName);
	   return userSecurityName;
	}
	
	/**
	* Maps a X.509 format certificate to a valid user in the registry.
	* This is used to map the name in the certificate supplied by a browser
	* to a valid userSecurityName in the registry
	*
	* @param     cert the X509 certificate chain
	* @return    The mapped name of the user userSecurityName
	* @exception CertificateMapNotSupportedException if the 
	*            particular certificate is not supported.
	* @exception CertificateMapFailedException if the mapping of 
	*            the certificate fails.
	* @exception CustomRegistryException if there is any registry
	*            -specific problem
	**/
	public String mapCertificate(X509Certificate[] cert)
	   throws CertificateMapNotSupportedException,
	          CertificateMapFailedException,
	          CustomRegistryException {
	   String name=null;
	   X509Certificate cert1 = cert[0];
	
		debug("mapCertificate()");
		
	   try {
	      // map the SubjectDN in the certificate to a userID.
	      name = cert1.getSubjectDN().getName();
	   } catch(Exception ex) {
	      throw new CertificateMapNotSupportedException(ex.getMessage(),ex);
	   }
	
	   if(!isValidUser(name)) {
	      throw new CertificateMapFailedException("user: " + name 
	      + " is not valid");
	   }
	   return name;
	}
	
	/**
	* Returns the realm of the registry.
	*
	* @return the realm. The realm is a registry-specific string 
	* indicating the realm or domain for which this registry 
	* applies. For example, for OS/400 or AIX this would be 
	* the host name of the system whose user registry this 
	* object represents. If null is returned by this method,
	* realm defaults to the value of "customRealm". It is 
	* recommended that you use your own value for realm.
	* 
	* @exception CustomRegistryException if there is any registry-
	* specific problem
	**/
	public String getRealm()
	   throws CustomRegistryException {
	   
	   return _realmName;
	}
	
	/**
	* Gets a list of users that match a pattern in the registry.
	* The maximum number of users returned is defined by the limit
	* argument.
	* This method is called by the administrative console and scripting 
	* (command line) to make the users in the registry available for 
	* adding them (users) to roles.
	*
	* @param      pattern the pattern to match. (For example, a* will 
	*             match  all userSecurityNames starting with a)
	* @param      limit the maximum number of users that should be
	*             returned. This is very useful in situations where 
	*             there are thousands of users in the registry and 
	*             getting all of them at once is not practical. The 
	*             default is 100. A value of 0 implies get all the
	*             users and hence must be used with care.
	* @return     a Result object that contains the list of users 
	*             requested and a flag to indicate if  more users
	*             exist.
	* @exception  CustomRegistryException if there is any registry-
	*             specificproblem
	**/
	public Result getUsers(String pattern, int limit)
	   throws CustomRegistryException {
	
		debug("getUsers()");
		
		// Can't implement this while org.jaalounge.AbstractLoginModule doesn't
		// Just return an empty result set
	   Result result = new Result();
	   result.setList(new ArrayList());
	   return result;
	}
	
	/**
	* Returns the display name for the user specified by 
	*  userSecurityName.
	*
	* This method may be called only when the user information
	* is displayed (information purposes only, for example, in 
	* the administrative console) and hence not used in the actual 
	* authentication or authorization purposes. If there are no 
	* display names in the registry return null or empty string.
	*
	* In WebSphere Application Server 4 custom registry, if you 
	* had a display name for the user and if it was different from the 
	* security name, the display name was returned for the EJB 
	* methods getCallerPrincipal() and the servlet methods
	* getUserPrincipal() and  getRemoteUser().
	* In WebSphere Application Server Version 5, for the same 
	* methods, the security name will be returned by default. This 
	* is the recommended way as the display name is not unique 
	* and might create security holes. However, for backward 
	* compatibility if one needs the display name to be returned 
	* set the property WAS_UseDisplayName to true.
	*
	*See the InfoCenter documentation for more information.
	*
	* @param     userSecurityName the name of the user.
	* @return    the display name for the user. The display 
	*            name is a registry-specific string that 
	*            represents a descriptive, not necessarily 
	*            unique, name for a user. If a display name 
	*            does not exist return null or empty string.
	* @exception EntryNotFoundException if userSecurityName 
	*            does not exist.
	* @exception CustomRegistryException if there is any registry- 
	 *           specific problem
	**/
	public String getUserDisplayName(String userSecurityName)
	   throws CustomRegistryException,
	          EntryNotFoundException {
	
		debug("getUserDisplayName(" + userSecurityName + ")");
		
		// Simple implementation with some basic checks...
		if (!_connected) {
			throw new EntryNotFoundException("No user logged in!");
		}
		if (!_loggedUserName.equals(userSecurityName)) {
			throw new EntryNotFoundException("User " + userSecurityName + " is not logged in!");
		}
	   return userSecurityName;
	}
	
	/**
	* Returns the unique ID for a userSecurityName. This method is called 
	* when creating a credential for a user.
	*
	* @param    userSecurityName - The name of the user.
	* @return   The unique ID of the user. The unique ID for an user 
	*           is the stringified form of some unique, registry-specific, 
	*           data that serves to represent the user. For example, for 
	*           the UNIX user registry, the unique ID for a user can be 
	*           the UID.
	* @exception EntryNotFoundException if userSecurityName does not 
	*            exist.
	* @exception CustomRegistryException if there is any registry-
	*            specific problem
	**/
	public String getUniqueUserId(String userSecurityName)
	   throws CustomRegistryException, 
	          EntryNotFoundException {
	
		debug("getUniqueUserId(" + userSecurityName + ")");
				
		// Simple implementation with some basic checks...
		if (!_connected) {
			throw new EntryNotFoundException("No user logged in!");
		}
		if (!_loggedUserName.equals(userSecurityName)) {
			throw new EntryNotFoundException("User " + userSecurityName + " is not logged in!");
		}
	
	   return userSecurityName;
	}
	
	/**
	* Returns the name for a user given its uniqueId.
	*
	* @param      uniqueUserId  - The unique ID of the user.
	* @return     The userSecurityName of the user.
	* @exception  EntryNotFoundException if the unique user ID does not exist.
	* @exception  CustomRegistryException if there is any registry-specific
	*             problem
	**/
	public String getUserSecurityName(String uniqueUserId)
	   throws CustomRegistryException,
	          EntryNotFoundException {
	
		debug("getUserSecurityName(" + uniqueUserId + ")");
		
		// Simple implementation with some basic checks...
		if (!_connected) {
			throw new EntryNotFoundException("No user logged in!");
		}
	
		if (!_loggedUserName.equals(uniqueUserId)) {
			throw new EntryNotFoundException("User " + uniqueUserId + " is not logged in! ("
					+ _loggedUserName + " is)");
		}
	
	   return _loggedUserName;
	}
	
	/**
	* Determines if the userSecurityName exists in the registry
	*
	* @param     userSecurityName - The name of the user
	* @return    True if the user is valid; otherwise false
	* @exception CustomRegistryException if there is any registry-
	*            specific problem
	* @exception RemoteException as this extends java.rmi.Remote 
	*            interface 
	**/
	public boolean isValidUser(String userSecurityName)
	   throws CustomRegistryException {
	
		debug("isValidUser(" + userSecurityName + ")");
		
		// Simple implementation with some basic checks...
		if (!_connected) {
			throw new CustomRegistryException("No user logged in!");
		}
		
		if (userSecurityName == _loggedUserName)
			return true;
	
	   return false;
	}
	
	
	/**
	* Gets a list of groups that match a pattern in the registry
	* The maximum number of groups returned is defined by the 
	* limit argument. This method is called by administrative console
	* and scripting (command line) to make available the groups in  
	* the registry for adding them (groups) to roles.
	*
	* @param       pattern the pattern to match. (For example, a* matches 
	*              all groupSecurityNames starting with a)
	* @param       Limits the maximum number of groups to return 
	*              This is very useful in situations where there 
	*              are thousands of groups in the registry and getting all 
	*              of them at once is not practical. The default is 100. 
	*              A value of 0 implies get all the groups and hence must 
	*              be used with care.
	* @return      A Result object that contains the list of groups 
	*              requested and a flag to indicate if more groups exist.
	* @exception CustomRegistryException if there is any registry-specific
	*              problem
	**/
	public Result getGroups(String pattern, int limit)
	   throws CustomRegistryException {
	
		debug("getGroups()");
		
		// Can't implement this while org.jaalounge.AbstractLoginModule doesn't
		// Just return an empty result set
	   Result result = new Result();
	   result.setList(new ArrayList());
	   return result;
	}
	
	/**
	* Returns the display name for the group specified by groupSecurityName.
	* For this version of WebSphere Application Server, the only usage of  
	* this method is by the clients (administrative console and scripting)   
	* to present a descriptive name of the user if it exists.
	*
	* @param groupSecurityName the name of the group.
	* @return  the display name for the group. The display name
	*          is a registry-specific string that represents a  
	*          descriptive, not necessarily unique, name for a group.  
	*          If a display name does not exist return null or empty 
	*          string.
	* @exception EntryNotFoundException if groupSecurityName does 
	*          not exist.
	* @exception CustomRegistryException if there is any registry-
	*          specific problem
	**/
	public String getGroupDisplayName(String groupSecurityName)
	   throws CustomRegistryException,
	          EntryNotFoundException {
	
		debug("getGroupDisplayName(" + groupSecurityName + ")");
		
		// Simple implementation
	   return groupSecurityName;
	}
	
	/**
	* Returns the Unique ID for a group.
	
	* @param     groupSecurityName the name of the group.
	* @return    The unique ID of the group. The unique ID for
	*            a group is the stringified form of some unique,
	*            registry-specific, data that serves to represent
	*            the group. For example, for the UNIX user registry,
	*            the unique ID might be the GID.
	* @exception EntryNotFoundException if groupSecurityName does 
	*            not exist.
	* @exception CustomRegistryException if there is any registry-
	*            specific problem
	* @exception RemoteException as this extends java.rmi.Remote
	**/
	public String getUniqueGroupId(String groupSecurityName)
	   throws CustomRegistryException,
	          EntryNotFoundException {
	
		debug("getUniqueGroupId(" + groupSecurityName + ")");
		
		// (very) simple implementation
	   return groupSecurityName;
	}
	
	/**
	* Returns the Unique IDs for all the groups that contain the UniqueId 
	* of a user. Called during creation of a user's credential.
	*
	* @param     uniqueUserId the unique ID of the user.
	* @return    A list of all the group unique IDs that the unique user 
	*            ID belongs to. The unique ID for an entry is the 
	*            stringified form of some unique, registry-specific, data 
	*            that serves to represent the entry.  For example, for the
	*            UNIX user registry, the unique ID for a group might be 
	*            the GID and the Unique ID for the user might be the UID.
	* @exception EntryNotFoundException if uniqueUserId does not exist.
	* @exception CustomRegistryException if there is any registry-specific
	*            problem
	**/
	public List getUniqueGroupIds(String uniqueUserId)
	   throws CustomRegistryException,
	          EntryNotFoundException {
		
		debug("getUniqueGroupIds(" + uniqueUserId + ")");
		
		ArrayList groupUniqueIds = new ArrayList();
		
		// Simple implementation with some basic checks...
		if (!_connected) {
			throw new EntryNotFoundException("No user logged in!");
		}
		
		if (!_loggedUserName.equals(uniqueUserId)) {
			throw new EntryNotFoundException("User " + uniqueUserId + " is not logged in! (" 
								+ _loggedUserName + " is)");
		}
	
		Subject subject = _loginContext.getSubject();
		if (subject == null)
			debug ("subject is null!");
		else {
		
			// implementation of AbstractLoginModule for websphere put in "principals"
			// list the user, followed by GroupPrincipal instances 
			// representing its groups (short names)
			Iterator it = subject.getPrincipals(GroupPrincipal.class).iterator();
			if (it == null)
				debug ("iterator is null!");
			else {
			   while (it.hasNext()) {
			   	GroupPrincipal groupPrincipal = (GroupPrincipal) it.next();
			   	debug ("group name: " + groupPrincipal.getName());
	
			   	groupUniqueIds.add(groupPrincipal.getName());
			   }
		   }
		}
	   
	   return groupUniqueIds;
	}
	
	/**
	* Returns the name for a group given its uniqueId.
	*
	* @param     uniqueGroupId the unique ID of the group.
	* @return    The name of the group.
	* @exception EntryNotFoundException if the uniqueGroupId does 
	*            not exist.
	* @exception CustomRegistryException if there is any registry-
	*            specific problem
	**/
	public String getGroupSecurityName(String uniqueGroupId)
	   throws CustomRegistryException,
	          EntryNotFoundException {
	
		debug("getGroupSecurityName(" + uniqueGroupId + ")");
	
	   return uniqueGroupId;
	}
	
	/**
	* Determines if the groupSecurityName exists in the registry
	*
	* @param     groupSecurityName the name of the group
	* @return    True if the groups exists; otherwise false
	* @exception CustomRegistryException if there is any registry-
	*            specific problem
	**/
	public boolean isValidGroup(String groupSecurityName)
	   throws CustomRegistryException {
	
		debug("isValidGroup(" + groupSecurityName + ")");
		
		// Don't know how to implement it!
	   return true;
	}
	
	/**
	* Returns the securityNames of all the groups that contain the user
	*
	* This method is called by the administrative console and scripting 
	* (command line) to verify the user entered for RunAsRole mapping  
	* belongs to that role in the roles to user mapping. Initially, the 
	* check is done to see  if the role contains the user. If the role does 
	* not contain the user explicitly, this method is called to get the groups 
	* that this user belongs to so that check can be made on the groups that 
	* the role contains.
	*
	* @param     userSecurityName the name of the user
	* @return    A list of all the group securityNames that the user
	*            belongs to.
	* @exception EntryNotFoundException if user does not exist.
	* @exception CustomRegistryException if there is any registry-
	*            specific problem
	* @exception RemoteException as this extends the java.rmi.Remote
	*            interface 
	**/
	public List getGroupsForUser(String userName)
	   throws CustomRegistryException,
	          EntryNotFoundException {
		debug("getGroupsForUser(" + userName + ")");
		
		// Redirect on getUniqueGroupIds(), which does the same things
		return getUniqueGroupIds(userName);
	}
	
	/**
	* Gets a list of users in a group.  
	*
	* The maximum number of users returned is defined by the 
	* limit argument.
	*
	
	* This method is being used by the process choreographer
	* when staff assignments are modeled using groups.
	*
	* In rare situations, if you are working with a registry where  
	* getting all the users from any of your groups is not practical   
	* (for example if there are a large number of users) you can throw
	* the NotImplementedException for that particular group. Make sure   
	* that if the process choreographer is installed (or if installed later) 
	* the staff assignments are not modeled using these particular groups.
	* If there is no concern about returning the users from groups 
	* in the registry it is recommended that this method be implemented
	* without throwing the NotImplemented exception.
	* @param         groupSecurityName the name of the group
	* @param         Limits the maximum number of users that should be 
	*                returned. This is very useful in situations where there 
	*                are lot of users in the registry and getting all of  
	*                them at once is not practical. A value of 0 implies   
	*                get all the users and hence must be used with care. 
	* @return        A result object that contains the list of users
	*                requested and a flag to indicate if more users exist.
	* @deprecated    This method will be deprecated in future.
	* @exception     NotImplementedException throw this exception in rare 
	*                situations if it is not practical to get this information   
	*                for any of the group or groups from the registry.
	* @exception     EntryNotFoundException if the group does not exist in 
	*                the registry
	* @exception     CustomRegistryException if there is any registry-specific 
	*                problem
	**/
	public Result getUsersForGroup(String groupSecurityName, int limit)
	   throws NotImplementedException,
	          EntryNotFoundException,
	          CustomRegistryException {
		
	   Result result = new Result();
	   result.setList(new ArrayList());
	   return result;
	}
	
	/**
	* This method is implemented internally by the WebSphere Application 
	* Server code in this release. This method is not called for the custom 
	* registry implementations for this release. Return null in the 
	* implementation.
	*
	**/
	public com.ibm.websphere.security.cred.WSCredential 
	      createCredential(String userSecurityName)
	      throws CustomRegistryException,
	             NotImplementedException,
	             EntryNotFoundException {
	
	   // This method is not called.
	   return null;
	}
	
	/**
	 * Method used to drill down into the WSLoginFailedException to find the 
	 * "root cause" exception from a JAAS login.
	 * 
	 * @param  e an exception of type LoginException.
	 * @return   the root cause login exception.
	 */ 
	public Throwable determineCause(Throwable e) {
	    Throwable root_exception = e, temp_exception = null;
	
	    // keep looping until there are no more embedded WSLoginFailedException
	    // or WSSecurityException exceptions
	    while (true) {
	        if (e instanceof com.ibm.websphere.security.auth.WSLoginFailedException) {
	            temp_exception = ((com.ibm.websphere.security.auth.WSLoginFailedException)
	            e).getCause();
	        } else if (e instanceof com.ibm.websphere.security.WSSecurityException) {
	            temp_exception = ((com.ibm.websphere.security.WSSecurityException)
	            e).getCause();
	        } else if (e instanceof javax.naming.NamingException) {
	            // check for LDAP embedded exception
	            temp_exception = ((javax.naming.NamingException)e).getRootCause();
	        // your custom processing here, if necessary    
	        // } else if (e instanceof your_custom_exception_here){
	        //
	        } else {
	            // this exception is not one of the types we are looking for,
	            // lets return now, this is the root from the WebSphere
	            // Application Server perspective
	            return root_exception;
	        }
	
	       if (temp_exception != null) {
	           // we have an exception, let's go back an see if this has another
	           // one embedded within it.
	           root_exception = temp_exception;
	           e = temp_exception;
	           continue;
	        } else {
	           // we finally have the root exception from this call path, this
	           // has to occur at some point
	           return root_exception;
	        }
	   } // end of while		
	} 
}

