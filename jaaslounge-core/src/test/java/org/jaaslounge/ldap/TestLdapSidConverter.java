package org.jaaslounge.ldap;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingException;

import junit.framework.TestCase;

public class TestLdapSidConverter extends TestCase {

    private String base;
    private static List<String> validSids;
    private static List<String> lotsOfSids;
    private static List<String> invalidSids;
    private static LdapSidConverter converter;

    private static final String SID_BASE = "\\01\\05\\00\\00\\00\\00\\00\\05\\15\\00\\00\\00\\02\\b7\\dd\\2a\\97\\52\\11\\68\\47\\29\\db\\ec";

    protected void setUp() {
        String path = this.getClass().getClassLoader().getResource("krb5.login.conf").toExternalForm();
        System.setProperty("java.security.auth.login.config", path.replace("%20", " "));
        System.setProperty("java.security.krb5.realm", "EX2003.COM"); 
        System.setProperty("java.security.krb5.kdc", "testad2003.ex2003.com"); 
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

        base = "DC=ex2003,DC=com";
        converter = new LdapSidConverter("ldap://testad2003:389", base, 600000);

        validSids = new ArrayList<String>();
        for(int i = 0; i < 8; i++) {
            validSids.add(SID_BASE + "\\0" + i + "\\02\\00\\00");
        }

        lotsOfSids = new ArrayList<String>();
        for(int i = 0; i < 1000; i++) {
            lotsOfSids.add(SID_BASE + "\\01\\02\\00\\00");
        }

        invalidSids = new ArrayList<String>();
        invalidSids.add(SID_BASE + "\\F5\\01\\00\\00");

    }

    public void testValidSids() {
        List<String> groupsNames = null;
        try {
            groupsNames = converter.getGroupNames(validSids);
            assertNotNull(groupsNames);
            assertEquals(validSids.size(), groupsNames.size());

        } catch(NamingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    public void testLotsOfSids() {
        List<String> groupsNames = null;
        try {
            groupsNames = converter.getGroupNames(lotsOfSids);
            assertNotNull(groupsNames);
        } catch(NamingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    public void testEmptySids() {
        List<String> groupsNames = null;
        try {
            groupsNames = converter.getGroupNames(new ArrayList<String>());
            assertNotNull(groupsNames);
            assertEquals(0, groupsNames.size());
        } catch(NamingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    public void testNullSids() {
        List<String> groupsNames = null;
        try {
            groupsNames = converter.getGroupNames(null);
            fail();
        } catch(NamingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch(NullPointerException e) {
            assertNotNull(e);
            assertNull(groupsNames);
        }
    }

    public void testInvalidSid() {
        List<String> groupsNames = null;
        try {
            groupsNames = converter.getGroupNames(invalidSids);
            assertNotNull(groupsNames);
            assertEquals(0, groupsNames.size());
        } catch(NamingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

}
