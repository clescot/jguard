/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles Lescot

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
package net.sf.jguard.core.authentication.callbackhandler;

import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import javax.inject.Inject;
import javax.security.auth.callback.CallbackHandler;
import java.util.Collection;

/**
 * this MockCallbackHandler is only a naive subclass of the common JGuardCallbackHandler.
 * callback detection and filling IS devoted to authenticationSchemeHandler.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockCallbackHandler extends JGuardCallbackHandler<MockRequest, MockResponse> implements CallbackHandler {


    @Inject
    public MockCallbackHandler(Request<MockRequest> request,
                               Response<MockResponse> response,
                               Collection<AuthenticationSchemeHandler<MockRequest, MockResponse>> authenticationSchemeHandlers) {

        super(request, response, authenticationSchemeHandlers);
    }

    /**
     * define if the communication between client and server is non-blocking (return <b>true</b>) or blocking (return <b>false</b>).
     *
     * @return
     */
    @Override
    protected boolean isAsynchronous() {
        return false;
    }

}
