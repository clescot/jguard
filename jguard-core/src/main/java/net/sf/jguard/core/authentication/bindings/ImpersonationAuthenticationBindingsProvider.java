/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2009  Charles GAY
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

package net.sf.jguard.core.authentication.bindings;

import javax.inject.Inject;
import com.google.inject.Provider;
import net.sf.jguard.core.technology.ImpersonationScopes;
import net.sf.jguard.core.technology.Scopes;
import net.sf.jguard.core.technology.StatefulImpersonationScopes;
import net.sf.jguard.core.technology.StatefulScopes;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public abstract class ImpersonationAuthenticationBindingsProvider implements Provider<ImpersonationScopes> {
    private Scopes scopes;
    private static final String HOOK = "HOOK";
    protected static final String LOGIN = "login";

    @Inject
    ImpersonationAuthenticationBindingsProvider(Scopes scopes) {
        this.scopes = scopes;
    }


    public ImpersonationScopes get() {

        ImpersonationScopes impersonatedScopes;
        if (scopes instanceof StatefulScopes) {
            impersonatedScopes = new StatefulImpersonationScopes((StatefulScopes) scopes);
        } else {
            impersonatedScopes = new ImpersonationScopes(scopes);
        }

        return impersonatedScopes;

    }

}
