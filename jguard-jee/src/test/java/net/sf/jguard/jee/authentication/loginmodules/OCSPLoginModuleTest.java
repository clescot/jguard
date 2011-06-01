/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name: v080beta1 $
http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles GAY

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


jGuard project home page:
http://sourceforge.net/projects/jguard/

*/
package net.sf.jguard.jee.authentication.loginmodules;

import javax.inject.Inject;
import net.sf.jguard.core.authentication.configuration.JGuardConfiguration;
import net.sf.jguard.ext.SecurityConstants;
import net.sf.jguard.ext.authentication.loginmodules.OCSPLoginModule;
import net.sf.jguard.ext.authentication.loginmodules.XmlLoginModule;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class OCSPLoginModuleTest extends CertificateBasedTestCase {

   @Inject
    public List<AppConfigurationEntry> appConfigurationEntries;
    
    public void setUp() throws Exception {
        super.setUp();
    }

    /**
     * to execute this test, you need to specify:
     * - the path to the XML file which contains users.
     * - ocspServerURL
     * - IssuerCACertLocation
     * - OcspSignerCertLocation
     *
     * @throws Exception
     */
    public void testOCSPAuthentication() throws Exception {
        if (!"false".equals(System.getProperty(SKIP_CERTIFICATE_TESTS))) {
            return;
        }
        setConfiguration(new JGuardConfiguration(APPLICATION_NAME, authenticationSettings,appConfigurationEntries));

        Map entry1Options = new HashMap();
        entry1Options.put("debug", "true");
        entry1Options.put(SecurityConstants.OCSP_SERVER_URL, "http://127.0.0.1:8080/ejbca/publicweb/status/ocsp");
        entry1Options.put(SecurityConstants.ISSUER_CA_CERT_LOCATION, "/home/charles/worspace_eclipse_3.2/jguard-jee/src/test/resources/AdminCA1.der");
        //entry1Options.put(SecurityConstants.OCSP_SIGNER_CERT_LOCATION, "/home/charles/worspace_eclipse_3.2/jguard-jee/src/test/resources/OCSPSignerCertificate.der");
        entry1Options.put(SecurityConstants.OCSP_SIGNER_CERT_LOCATION, "/home/charles/worspace_eclipse_3.2/jguard-jee/src/test/resources/AdminCA1.der");
        AppConfigurationEntry entry1 = new AppConfigurationEntry(OCSPLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entry1Options);

        List appEntries = new ArrayList();
        appEntries.add(entry1);
        Map entry2Options = new HashMap();
        entry2Options.put("debug", "true");
        AppConfigurationEntry entry2 = new AppConfigurationEntry(XmlLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, entry2Options);
        appEntries.add(entry2);
        configuration.addConfigEntriesForApplication(APPLICATION_NAME, appEntries);
        LoginContext localLoginContext = new LoginContext(APPLICATION_NAME, new Subject(), cbh, configuration);
        localLoginContext.login();
        Subject subject = localLoginContext.getSubject();
        System.out.println(subject);
    }

}
