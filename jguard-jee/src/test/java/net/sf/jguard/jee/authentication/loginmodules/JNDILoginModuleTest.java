/*
 jGuard is a security framework based on top of jaas (java authentication and authorization security).
 it is written for web applications, to resolve simply, access control problems.
 version $Name$
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

import com.kizna.servletunit.HttpServletRequestSimulator;
import com.kizna.servletunit.HttpServletResponseSimulator;
import junit.framework.TestCase;
import net.sf.jguard.ext.authentication.loginmodules.JNDILoginModule;
import net.sf.jguard.jee.authentication.callbacks.HttpServletCallbackHandler;

import javax.naming.Context;
import javax.naming.directory.SearchControls;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * to enable this test, set "jndi.test.skip" system property to "false".
 * class used to unit test JNDILoginModule class.
 * a better unit test would be based on
 * <a href="http://directory.apache.org/apacheds/1.0/using-apacheds-for-unit-tests.html">this page</a>
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles GAY</a>
 */
public class JNDILoginModuleTest extends TestCase {

    private static final String SKIP_JNDI_TESTS = "jndi.test.skip";
    private static JNDILoginModule lm = null;

    /*
      * Test method for 'net.sf.jguard.authentication.loginmodules.JNDILoginModule.initialize(Subject, CallbackHandler, Map, Map)'
      */
    public void testInitialize() {
        if (!"false".equals(System.getProperty(SKIP_JNDI_TESTS))) {
            return;
        }

        String login = "login";
        //HttpServletCallbackHandler2.setLoginField(login);
        String password = "password";
        //HttpServletCallbackHandler2.setPasswordField(password);
        HttpServletRequestSimulator request = new HttpServletRequestSimulator();
        request.addParameter(login, "mysamaccountname");
        request.addParameter(password, "toto");
        HttpServletResponseSimulator response = new HttpServletResponseSimulator();
        //HttpServletCallbackHandler.setAuthSchemes(HttpConstants.FORM_AUTH);
        HttpServletCallbackHandler cbh = null;//new HttpServletCallbackHandler(request, response);
        lm = new JNDILoginModule();
        Map state = new HashMap();
        Map env = new HashMap();
        env.put("preauth." + "com.sun.jndi.ldap.connect.pool", "true");
        env.put("preauth." + "com.sun.jndi.ldap.connect.pool.prefsize", "5");
        env.put("preauth." + Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("preauth." + Context.PROVIDER_URL, "ldap://myserver:389");
        env.put("preauth." + Context.SECURITY_AUTHENTICATION, "none");
        env.put("preauth." + "searchcontrols." + "searchscope", Integer.toString(SearchControls.SUBTREE_SCOPE));
        env.put("preauth." + "search.base.dn", "dc=toto,dc=com");
        env.put("preauth." + "search.filter", "(&(samAccountName={0})(!(proxyAddresses=*)))");


        env.put("authenticationManager." + "com.sun.jndi.ldap.connect.pool", "true");
        env.put("authenticationManager." + "com.sun.jndi.ldap.connect.pool.prefsize", "5");

        env.put("authenticationManager." + Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("authenticationManager." + Context.PROVIDER_URL, "ldap://myserver:389");
        env.put("authenticationManager." + Context.SECURITY_AUTHENTICATION, "simple");


        //env.put("contextforcommit", "preauth");

        lm.initialize(new Subject(), cbh, state, env);

    }

    /*
      * Test method for 'net.sf.jguard.authentication.loginmodules.JNDILoginModule.login()'
      */
    public void testLogin() {
        if (!"false".equals(System.getProperty(SKIP_JNDI_TESTS))) {
            return;
        }

        testInitialize();
        try {
            LogManager logManager = LogManager.getLogManager();
            Enumeration loggerNames = logManager.getLoggerNames();
            while (loggerNames.hasMoreElements()) {
                String loggerName = (String) loggerNames.nextElement();
                Logger logger = logManager.getLogger(loggerName);
                logger.setLevel(Level.FINEST);
            }
            boolean loginOK = lm.login();
        } catch (LoginException e) {
            TestCase.fail(e.getMessage());
        }
    }

    /*
      * Test method for 'net.sf.jguard.authentication.loginmodules.JNDILoginModule.commit()'
      */
    public void testCommit() {
        if (!"false".equals(System.getProperty(SKIP_JNDI_TESTS))) {
            return;
        }

        testInitialize();
        testLogin();
        try {
            boolean commitOK = lm.commit();
        } catch (LoginException e) {
            TestCase.fail(e.getMessage());
        }
    }

}
