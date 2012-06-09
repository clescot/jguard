/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2009  Charles Lescot
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * jGuard project home page:
 * http://sourceforge.net/projects/jguard/
 */

package net.sf.jguard.core.authentication.schemes;

import com.google.inject.Singleton;
import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.inject.Inject;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.FilePermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.ArrayList;
import java.util.Collection;

@Singleton
public class DummyAuthenticationSchemeHandler<Req extends Request, Res extends Response> implements StatefulAuthenticationSchemeHandler<Req, Res> {
    private PermissionCollection grantedPermissions;
    public static final String MOCK_AUTHENTICATION_SCHEME_HANDLER_NAME = "MOCK";
    private static final String DUMMY_NAME_PERMISSION = "dummy";
    private static final String DUMMY_ACTIONS_PERMISSION = "dummy";
    private boolean answerToChallenge = true;
    private boolean challengeNeeded = false;
    private static final String GRANTED_PERMISSION_NAME = "grantedName";
    private static final String GRANTED_PERMISSION_ACTIONS = "grantedActions";

    @Inject
    public DummyAuthenticationSchemeHandler() {
        grantedPermissions = new JGPositivePermissionCollection();
        grantedPermissions.add(new URLPermission(GRANTED_PERMISSION_NAME, GRANTED_PERMISSION_ACTIONS));
    }

    public Permission getLogoffPermission() {
        return new FilePermission(DUMMY_NAME_PERMISSION, DUMMY_ACTIONS_PERMISSION);
    }

    public String getName() {
        return MOCK_AUTHENTICATION_SCHEME_HANDLER_NAME;
    }

    public Collection<Class<? extends Callback>> getCallbackTypes() {
        ArrayList<Class<? extends Callback>> classes = new ArrayList<Class<? extends Callback>>();
        classes.add(NameCallback.class);
        classes.add(PasswordCallback.class);
        return classes;
    }

    public boolean answerToChallenge(Req request, Res response) {
        return answerToChallenge;
    }

    public boolean impliesChallenge() {
        return challengeNeeded;
    }


    public void buildChallenge(Req request, Res response) {

    }

    public PermissionCollection getGrantedPermissions() {
        return grantedPermissions;
    }

    public void authenticationSucceed(Subject subject, Req request, Res response) {

    }

    public void authenticationFailed(Req request, Res response) {

    }

    public void handleSchemeCallbacks(Req request, Res response, Callback[] cbks) throws UnsupportedCallbackException {

    }

    public void setAnswerToChallenge(boolean answerToChallenge) {
        this.answerToChallenge = answerToChallenge;
    }

    public void setChallengeNeeded(boolean challengeNeeded) {
        this.challengeNeeded = challengeNeeded;
    }
}
