22/12/2009

Le support de Weblogic par JaasLounge SSO est réalisé par un MBean Weblogic.

Weblogic fourni un outil 'weblogic.management.commo.WebLogicMBeanMaker' permettant :
- La génération de squelettes de fichiers à partir d'une description XML (data/JaasLoungeIdentityAsserter.xml)
- Le packaging des fichiers en un fichier jar pouvant s'intégrer dans Weblogic

L'intégration avec Maven de cet outil n'est que partielle :
- Seule l'étape de packaging est appelée. (voir pom.xml)
- Un installation compléte de Weblogic est requise. (dans C:\bea)
- Le classpath doit étre correctement installé par l'appel de C:\bea\wlserver_10.3\server\bin\setWLSEnv.cmd

Le fichier généré est déposé dans target\mbeans\jaaslounge-sso-weblogic-X.X.X.jar


