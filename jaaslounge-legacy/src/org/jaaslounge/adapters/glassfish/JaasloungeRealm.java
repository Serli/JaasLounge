/*
 * Created on 16 févr. 2006
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package org.jaaslounge.adapters.glassfish;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Level;

import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;

/**
 * @author jérôme
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class JaasloungeRealm extends IASRealm {

	public static final String AUTH_TYPE = "Jaaslounge";
	
	private HashMap groupCache = null;
	private Vector emptyVector =null;
	private Map _options=null;
	
	public Map getOptions() {
		return _options;
	}
	
	protected void init(Properties props) throws BadRealmException, NoSuchRealmException {
		_logger.log(Level.CONFIG,"JaasloungeRealm.init "+props.toString());
		
		_options=new HashMap();
		
		_options.putAll(props);
		
		String jaasCtx = props.getProperty(IASRealm.JAAS_CONTEXT_PARAM);
        
        if (jaasCtx==null) {
            _logger.warning("realmconfig.noctx");
            
            throw new BadRealmException("no jaas context");
        }
        
        String jaasloungeCtx = props.getProperty("jaaslounge-module");
        
        if (jaasloungeCtx==null) {
        	_logger.log(Level.WARNING,"JaasloungeRealm.init : no jaaslounge module");
            
            throw new BadRealmException("no jaaslounge module");
        }
        
        
		groupCache = new HashMap();
        emptyVector = new Vector();
        
        this.setProperty(IASRealm.JAAS_CONTEXT_PARAM, jaasCtx);
        this.setProperty("jaaslounge-module",jaasloungeCtx);
        
	}
	
	/**
     * Returns a short (preferably less than fifteen characters) description
     * of the kind of authentication which is supported by this realm.
     *
     * @return Description of the kind of authentication that is directly
     *     supported by this realm.
     */
    public String getAuthType()
    {
    	_logger.log(Level.CONFIG,"JaasloungeRealm.getAuthType");
        return AUTH_TYPE;
    }

	/**
     * Returns the name of all the groups that this user belongs to.
     * Note that this information is only known after the user has
     * logged in. This is called from web path role verification, though
     * it should not be.
     *
     * @param username Name of the user in this realm whose group listing
     *     is needed.
     * @return Enumeration of group names (strings).
     * @exception InvalidOperationException thrown if the realm does not
     *     support this operation - e.g. Certificate realm does not support
     *     this operation.
     */
    public Enumeration getGroupNames (String username)
        throws InvalidOperationException, NoSuchUserException
    {
    	_logger.log(Level.CONFIG,"JaasloungeRealm.getGroupNames "+username);
        Vector v = (Vector)groupCache.get(username);
        if (v == null) {
            if (_logger.isLoggable(Level.FINE)) {
                _logger.log(Level.FINE, "No groups available for: "+username);
            }
            return emptyVector.elements();
        } else {
            return v.elements();
        }
    }
    
    /**
     * Set group membership info for a user.
     * 
     */
    public void setGroupNames(String username, String[] groups)
    {
        Vector v = new Vector(groups.length);
        for (int i=0; i<groups.length; i++) {
            v.add(groups[i]);
        }
        _logger.log(Level.CONFIG,"JaasloungeRealm.setGroupNames "+username+" "+v.toString());
        groupCache.put(username, v);
    }

}
