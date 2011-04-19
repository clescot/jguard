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

import com.octo.captcha.module.config.CaptchaModuleConfig;
import com.octo.captcha.service.CaptchaService;
import com.octo.captcha.service.CaptchaServiceException;
import net.sf.jguard.ext.authentication.callbacks.JCaptchaCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.Map;

/**
 * <a href="http://jcaptcha.sourceforge.net/">JCaptcha</a> integration.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class JCaptchaLoginModule implements LoginModule {
    private static Logger logger = LoggerFactory.getLogger(JCaptchaLoginModule.class.getName());
    private static final String CAPTCHA_ANSWER_FIELD = "captchaAnswerField";

    private CallbackHandler callbackHandler;
    private boolean loginOK = true;
    private Class serviceClass;

    public void initialize(Subject subj, CallbackHandler cbkHandler, Map sState, Map opts) {
        this.callbackHandler = cbkHandler;
        String captchaAnswerField = (String) opts.get(JCaptchaLoginModule.CAPTCHA_ANSWER_FIELD);
        if (captchaAnswerField == null || captchaAnswerField.equals("")) {
            captchaAnswerField = "captchaAnswer";
        }

        try {
            serviceClass = Thread.currentThread().getContextClassLoader().loadClass(CaptchaModuleConfig.getInstance().getServiceClass());
        } catch (ClassNotFoundException e) {
            logger.error(" JCaptcha service class cannot be found ");
        }
    }

    public boolean login() throws LoginException {
        String sessionID = "-1";
        String captchaAnswer = "";
        boolean skipJCaptchaChallenge = false;

        if (callbackHandler == null) {
            loginOK = false;
            throw new JCaptchaLoginException("there is no CallbackHandler to validate  the JCaptcha Answer");
        }
        Callback[] callbacks = new Callback[1];
        callbacks[0] = new JCaptchaCallback();

        CaptchaService service;
        try {
            callbackHandler.handle(callbacks);
            JCaptchaCallback jcaptchaCallback = (JCaptchaCallback) callbacks[0];
            captchaAnswer = jcaptchaCallback.getCaptchaAnswer();
            skipJCaptchaChallenge = jcaptchaCallback.isSkipJCaptchaChallenge();
            sessionID = jcaptchaCallback.getSessionID();
            logger.debug("session ID=" + sessionID);

            if (skipJCaptchaChallenge) {
                logger.debug(" skip JCaptcha challenge set to true . JCaptcha challenge is ignored ");
                return false;
            }

            try {
                service = (CaptchaService) serviceClass.newInstance();
                logger.debug("service=" + service);
            } catch (InstantiationException e) {
                throw new LoginException(e.getMessage());
            } catch (IllegalAccessException e) {
                throw new LoginException(e.getMessage());
            }

            if (service == null) {
                loginOK = false;
                throw new JCaptchaLoginException(" JCaptcha service is null: it has not been properly initialized ");
            }
        } catch (IOException e) {
            loginOK = false;
            logger.error(e.getMessage());
            throw new JCaptchaLoginException(e);
        } catch (UnsupportedCallbackException e) {
            loginOK = false;
            throw new JCaptchaLoginException(e.getMessage());
        }
        Boolean valid = null;
        try {
            valid = service.validateResponseForID(sessionID, captchaAnswer);
        } catch (CaptchaServiceException e) {
            logger.warn(e.getMessage());
            loginOK = false;
            throw new JCaptchaLoginException(e);
        }

        if (!valid) {
            loginOK = false;
            throw new JCaptchaLoginException(" invalid JCaptcha Answer ");
        }

        logger.debug(" JCaptcha challenge succeed ");
        return true;
    }

    public boolean commit() throws LoginException {
        return loginOK;
    }

    public boolean abort() throws LoginException {
        return true;
    }

    public boolean logout() throws LoginException {
        return true;
    }

}
