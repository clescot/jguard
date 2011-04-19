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
package net.sf.jguard.ext.authentication.callbacks;

import javax.security.auth.callback.Callback;


/**
 * container for request and answer from the CAPTCHA Challenge.
 */
public class JCaptchaCallback implements Callback {

    private String sessionID;
    private String captchaAnswer;
    private boolean skipJCaptchaChallenge;

    public JCaptchaCallback() {
    }

    public final String getSessionID() {
        return sessionID;
    }

    public final void setSessionID(String sessionID) {
        this.sessionID = sessionID;
    }

    public final String getCaptchaAnswer() {
        return captchaAnswer;
    }

    public final void setCaptchaAnswer(String captchaAnswerField) {
        this.captchaAnswer = captchaAnswerField;
    }


    public boolean isSkipJCaptchaChallenge() {
        return skipJCaptchaChallenge;
    }

    public void setSkipJCaptchaChallenge(boolean skipJCaptchaChallenge) {
        this.skipJCaptchaChallenge = skipJCaptchaChallenge;
    }

}
