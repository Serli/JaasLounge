package org.jaaslounge.ldaplm;

import java.util.*;
import javax.security.auth.login.*;

import org.jaaslounge.*;

public class LDAPLoginModule extends AbstractLoginModule
{
  // Membergroup name
  private List _userGroups;

  public LDAPLoginModule()
  {
    // nothing todo
  }

  protected void _initialize()
  {
    // nothing todo
  }

  public void authenticate() throws FailedLoginException
  {
    try
    {
      // Init LDAP Class with Options, Debug, Username and Password
      LDAPReader ldap = new LDAPReader(getOptions(),isDebug(),getUsername(),getPassword());
      // Connect to Ldap Server and read information
      ldap.connect();
      // get Groups where the user is member off
      _userGroups = ldap.getMemberGroups();

    }catch(java.lang.Exception ex)
    {
      if (isDebug())
        System.out.println("[" + this.getClass().getName() + "]: LDAPLoginModule::authenicate: " + ex.getMessage());

      throw new FailedLoginException(ex.getMessage());
    }
  }

  public Collection getUserGroups()
  {
    if (isDebug())
    {
      for (int i = 0; i < _userGroups.size(); i++) {
        System.out.println("[" + this.getClass().getName() + "]: LDAPLoginModule::getUserGroups=" + _userGroups.toArray()[i]);
      }
    }
    // Return Member Groupnames
    return _userGroups;
  }
}
