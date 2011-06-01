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
import junit.framework.TestCase;
import net.sf.jguard.core.authentication.configuration.AuthenticationConfigurationSettings;
import net.sf.jguard.core.authentication.configuration.JGuardConfiguration;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.test.JGuardTestFiles;
import net.sf.jguard.ext.authentication.loginmodules.OCSPLoginModule;
import net.sf.jguard.jee.authentication.callbacks.HttpServletCallbackHandler;
import net.sf.jguard.jee.authentication.http.HttpServletRequestSimulator;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Map;

public abstract class CertificateBasedTestCase extends TestCase {

    protected JGuardConfiguration configuration = null;
    protected HttpServletCallbackHandler cbh = null;
    protected static String APPLICATION_NAME = "myApp";

    protected static final String SKIP_CERTIFICATE_TESTS = "certificate.test.skip";
    @Inject
    public AuthenticationManager authenticationManager;
    @Inject
    @AuthenticationConfigurationSettings
    public Map<String, Object> authenticationSettings;

    protected static final String JGUARD_AUTHENTICATION_XML = JGuardTestFiles.J_GUARD_AUTHENTICATION_XML.toString();
    protected URL authenticationConfigurationLocation;

    public void setUp() throws Exception {
        if (!"false".equals(System.getProperty(SKIP_CERTIFICATE_TESTS))) {
            return;
        }
        try {
            super.setUp();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

        authenticationConfigurationLocation = Thread.currentThread().getContextClassLoader().getResource(JGUARD_AUTHENTICATION_XML);

        URL url = getClass().getResource("/OCSPTestUsersPrincipals.xml");

        HttpServletRequestSimulator request = new HttpServletRequestSimulator();
        request.setScheme("https");
        request.setSecure(true);
        X509Certificate[] certificates = new X509Certificate[1];
        URL url2 = new URL(url, "superAdmin.der");
        X509Certificate certificate = OCSPLoginModule.getCertFromFile(url2.toString());
        certificates[0] = certificate;
        request.setAttribute("javax.servlet.request.X509Certificate", certificates);

    }


    public void setConfiguration(JGuardConfiguration configuration) {
        this.configuration = configuration;
    }

}
