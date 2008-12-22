package org.jaaslounge.tools;

import java.awt.*;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import org.jaaslounge.ntlm.NtlmLoginModule;
import java.util.HashMap;
import org.jaaslounge.ldaplm.LDAPReader;
import java.util.Map;

public class CTestDialog extends JDialog
{
  JPanel panel1 = new JPanel();
  BorderLayout borderLayout1 = new BorderLayout();
  JPanel m_jPanelCenter = new JPanel();
  JPanel m_jPanelSouth = new JPanel();
  JPanel m_jPanelNorth = new JPanel();
  JTextField m_txtLoginConfig = new JTextField();
  JLabel jLabel1 = new JLabel();
  JTextField m_txtLDAPServerURL = new JTextField();
  JLabel jLabel2 = new JLabel();
  JTextField m_txtLDAPInitialContextFactory = new JTextField();
  JLabel jLabel3 = new JLabel();
  JLabel jLabel4 = new JLabel();
  JTextField m_txtLDAPSuperUserContext = new JTextField();
  JButton m_btnConnectLDAP = new JButton();
  JLabel m_txtLDAP = new JLabel();
  JLabel m_lblNTLM = new JLabel();
  JLabel m_lblHost = new JLabel();
  JLabel m_lblDomain = new JLabel();
  JLabel m_lblUser = new JLabel();
  JLabel m_lblPasswd = new JLabel();
  JTextField m_txtHostname = new JTextField();
  JTextField m_txtDomain = new JTextField();
  JTextField m_txtUser = new JTextField();
  JPasswordField m_txtPasswd = new JPasswordField();
  JButton m_btnNtlm = new JButton();
  JLabel m_lblDefault = new JLabel();

  public CTestDialog(Frame owner, String title, boolean modal)
  {
    super(owner, title, modal);
    try
    {
      setDefaultCloseOperation(DISPOSE_ON_CLOSE);
      jbInit();
      pack();
    }
    catch (Exception exception)
    {
      exception.printStackTrace();
    }
  }

  public CTestDialog()
  {
    this(new Frame(), "CTestDialog", false);
  }

  private void jbInit() throws Exception
  {
    panel1.setLayout(borderLayout1);
    m_jPanelCenter.setLayout(null);
    m_txtLoginConfig.setText("<PATH CONFIG FILE>");
    m_txtLoginConfig.setBounds(new Rectangle(220, 25, 250, 21));
    jLabel1.setText("java.security.auth.login.config:");
    jLabel1.setBounds(new Rectangle(25, 25, 190, 17));
    m_txtLDAPServerURL.setToolTipText("");
    m_txtLDAPServerURL.setText("ldap://<SERVERNAME>:389");
    m_txtLDAPServerURL.setBounds(new Rectangle(220, 50, 250, 21));
    jLabel2.setText("LDAPServerURL:");
    jLabel2.setBounds(new Rectangle(25, 50, 190, 17));
    m_txtLDAPInitialContextFactory.setText("com.sun.jndi.ldap.LdapCtxFactory");
    m_txtLDAPInitialContextFactory.setBounds(new Rectangle(220, 75, 250, 21));
    jLabel3.setText("LDAPInitialContextFactory:");
    jLabel3.setBounds(new Rectangle(25, 75, 190, 17));
    jLabel4.setText("LDAPSuperUserContext:");
    jLabel4.setBounds(new Rectangle(25, 100, 190, 17));
    m_txtLDAPSuperUserContext.setText("DC=<DOMAIN>,DC=AT");
    m_txtLDAPSuperUserContext.setBounds(new Rectangle(220, 100, 250, 21));
    m_btnConnectLDAP.setBounds(new Rectangle(280, 320, 100, 25));
    m_btnConnectLDAP.setForeground(Color.red);
    m_btnConnectLDAP.setMargin(new Insets(2, 2, 2, 2));
    m_btnConnectLDAP.setText("connect Ldap");
    m_btnConnectLDAP.addActionListener(new CTestDialog_m_btnConnectLDAP_actionAdapter(this));
    m_txtLDAP.setFont(new java.awt.Font("Dialog", 1, 11));
    m_txtLDAP.setForeground(Color.red);
    m_txtLDAP.setText("LDAP:");
    m_txtLDAP.setBounds(new Rectangle(25, 0, 78, 15));
    m_lblNTLM.setFont(new java.awt.Font("Dialog", 1, 11));
    m_lblNTLM.setForeground(Color.blue);
    m_lblNTLM.setText("NTLM:");
    m_lblNTLM.setBounds(new Rectangle(25, 125, 190, 17));
    m_lblHost.setText("Hostname:");
    m_lblHost.setBounds(new Rectangle(25, 150, 190, 17));
    m_lblDomain.setText("Domain:");
    m_lblDomain.setBounds(new Rectangle(25, 175, 190, 17));
    m_lblUser.setText("User:");
    m_lblUser.setBounds(new Rectangle(25, 250, 190, 17));
    m_lblPasswd.setText("Passwd:");
    m_lblPasswd.setBounds(new Rectangle(25, 275, 190, 17));
    m_txtHostname.setText("");
    m_txtHostname.setBounds(new Rectangle(220, 150, 250, 21));
    m_txtDomain.setText("");
    m_txtDomain.setBounds(new Rectangle(220, 175, 250, 21));
    m_txtUser.setText("");
    m_txtUser.setBounds(new Rectangle(220, 250, 250, 21));
    m_txtPasswd.setText("");
    m_txtPasswd.setBounds(new Rectangle(220, 275, 250, 21));
    m_btnNtlm.setBounds(new Rectangle(150, 320, 100, 25));
    m_btnNtlm.setForeground(Color.blue);
    m_btnNtlm.setMargin(new Insets(2, 2, 2, 2));
    m_btnNtlm.setText("connect Ntlm");
    m_btnNtlm.addActionListener(new CTestDialog_m_btnNtlm_actionAdapter(this));
    this.setName("Test Connection");
    m_lblDefault.setFont(new java.awt.Font("Dialog", 1, 11));
    m_lblDefault.setForeground(new Color(0, 180, 0));
    m_lblDefault.setText("Default:");
    m_lblDefault.setBounds(new Rectangle(25, 225, 190, 17));
    panel1.setPreferredSize(new Dimension(500, 380));
    getContentPane().add(panel1);
    panel1.add(m_jPanelCenter, java.awt.BorderLayout.CENTER);
    m_jPanelCenter.add(jLabel1);
    m_jPanelCenter.add(jLabel2);
    m_jPanelCenter.add(m_txtLoginConfig);
    m_jPanelCenter.add(m_txtLDAPServerURL);
    m_jPanelCenter.add(jLabel3);
    m_jPanelCenter.add(jLabel4);
    m_jPanelCenter.add(m_txtLDAPSuperUserContext);
    m_jPanelCenter.add(m_txtLDAPInitialContextFactory);
    m_jPanelCenter.add(m_txtLDAP);
    m_jPanelCenter.add(m_lblNTLM);
    m_jPanelCenter.add(m_lblHost);
    m_jPanelCenter.add(m_lblDomain);
    m_jPanelCenter.add(m_lblUser);
    m_jPanelCenter.add(m_lblPasswd);
    m_jPanelCenter.add(m_txtHostname);
    m_jPanelCenter.add(m_txtDomain);
    m_jPanelCenter.add(m_txtUser);
    m_jPanelCenter.add(m_txtPasswd);
    m_jPanelCenter.add(m_btnConnectLDAP);
    m_jPanelCenter.add(m_btnNtlm);
    m_jPanelCenter.add(m_lblDefault, null);
    panel1.add(m_jPanelSouth, java.awt.BorderLayout.SOUTH);
    panel1.add(m_jPanelNorth, java.awt.BorderLayout.NORTH);
  }

  public boolean CheckInputValues()
  {
    if (m_txtUser.getText().length()==0) // Check Field length
    {
        JOptionPane.showMessageDialog(this,"Username missing!!","Username",JOptionPane.ERROR_MESSAGE);
        return false;
    }

    if (m_txtPasswd.getPassword().length==0) // Check Field length
    {
        JOptionPane.showMessageDialog(this,"Password missing!!","Password",JOptionPane.ERROR_MESSAGE);
        return false;
    }

    return true;
  }

  public void m_btnNtlm_actionPerformed(ActionEvent e)
  {
    // Use NTLM Login Module for Authetication

    if (CheckInputValues())
    {
      NtlmLoginModule nt=new NtlmLoginModule(this.m_txtHostname.getText(),this.m_txtDomain.getText());
      nt.connect(this.m_txtUser.getText(),new String(this.m_txtPasswd.getPassword()));
    }
  }

  public void m_btnConnectLDAP_actionPerformed(ActionEvent e)
  {
      // Use LDAP Login Module for Authentication

      if (CheckInputValues())
      {
        try
        {
          // wird durch den Tomcat gesetzt
          System.setProperty("java.security.auth.login.config",this.m_txtLoginConfig.getText());
          Map map = new HashMap();

          map.put("LDAPServerURL", this.m_txtLDAPServerURL.getText());
          map.put("LDAPInitialContextFactory",this.m_txtLDAPInitialContextFactory.getText());
          map.put("LDAPSuperUserContext", this.m_txtLDAPSuperUserContext.getText());

          LDAPReader l = new LDAPReader(map, true, this.m_txtUser.getText(),this.m_txtPasswd.getPassword());
          l.connect();
        }
        catch (Exception ex)
        {
          System.out.println(ex.getMessage());
        }
      }
  }
}

class CTestDialog_m_btnConnectLDAP_actionAdapter implements ActionListener
{
  private CTestDialog adaptee;

  CTestDialog_m_btnConnectLDAP_actionAdapter(CTestDialog adaptee)
  {
    this.adaptee = adaptee;
  }

  public void actionPerformed(ActionEvent e)
  {
    adaptee.m_btnConnectLDAP_actionPerformed(e);
  }
}

class CTestDialog_m_btnNtlm_actionAdapter implements ActionListener
{
  private CTestDialog adaptee;
  CTestDialog_m_btnNtlm_actionAdapter(CTestDialog adaptee)
  {
    this.adaptee = adaptee;
  }

  public void actionPerformed(ActionEvent e)
  {
    adaptee.m_btnNtlm_actionPerformed(e);
  }
}
