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

package net.sf.jguard.ext.authentication.loginmodules;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.*;
import java.util.Map.Entry;

/**
 * provide a facade to aggregate use of some loginModules as only one.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class FacadeLoginModule implements LoginModule {
    private List<LoginModule> loginModules = null;
    public static final String LOGINMODULES = "loginmodules";
    private static final Logger logger = LoggerFactory.getLogger(FacadeLoginModule.class.getName());

    /**
     * Creates a new instance of NestedLoginModule
     */
    public FacadeLoginModule() {

    }

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {

        loginModules = new ArrayList<LoginModule>();
        String loginModulesClasses = (String) options.get(LOGINMODULES);
        List classNames = Arrays.asList(loginModulesClasses.split(","));

        for (Object className1 : classNames) {
            String className = (String) className1;
            Class clazz;
            try {
                clazz = Class.forName(className, true, Thread.currentThread().getContextClassLoader());
                LoginModule lm = (LoginModule) clazz.newInstance();
                loginModules.add(lm);
            } catch (ClassNotFoundException ex) {
                logger.error(ex.getMessage(), ex);
            } catch (InstantiationException ex) {
                logger.error(ex.getMessage(), ex);
            } catch (IllegalAccessException ex) {
                logger.error(ex.getMessage(), ex);
            }
        }

        //build the options map dedicated to each nested loginmodule
        for (LoginModule loginModule : loginModules) {
            Set entries = options.entrySet();
            Iterator itEntries = entries.iterator();
            Map lmOptions = new HashMap();
            String className = loginModule.getClass().getName();
            //from the global Map,we create a specific map for each nested loginmodule
            while (itEntries.hasNext()) {
                Entry entry = (Entry) itEntries.next();
                if (entry.getKey().equals(className)) {
                    lmOptions.put(entry.getKey(), entry.getValue());
                }
            }
            loginModule.initialize(subject, callbackHandler, sharedState, lmOptions);
        }
    }

    public boolean login() throws LoginException {
        for (Object loginModule : loginModules) {
            LoginModule lm = (LoginModule) loginModule;
            lm.login();
        }
        return true;
    }

    public boolean commit() throws LoginException {
        for (Object loginModule : loginModules) {
            LoginModule lm = (LoginModule) loginModule;
            lm.commit();
        }
        return true;
    }

    public boolean abort() throws LoginException {
        for (Object loginModule : loginModules) {
            LoginModule lm = (LoginModule) loginModule;
            lm.abort();
        }
        return true;
    }

    public boolean logout() throws LoginException {
        for (Object loginModule : loginModules) {
            LoginModule lm = (LoginModule) loginModule;
            lm.logout();
        }
        return true;
    }

}
 