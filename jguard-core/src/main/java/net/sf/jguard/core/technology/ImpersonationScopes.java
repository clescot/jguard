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
package net.sf.jguard.core.technology;

import com.google.inject.servlet.RequestScoped;

import javax.inject.Inject;
import java.util.HashMap;
import java.util.Map;

/**
 * provides its own request and application attributes maps.
 * it does not rely on the underlying authenticationBindings on these attributes.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
@RequestScoped
public class ImpersonationScopes extends ScopesWrapper {
    private Map<String, Object> requestAttributes = null;
    private Map<String, Object> applicationAttributes = null;

    /**
     * @param scopes wrapped Scopes
     */
    @Inject
    public ImpersonationScopes(Scopes scopes) {
        super(scopes);
        requestAttributes = new HashMap<String, Object>();
        applicationAttributes = new HashMap<String, Object>();

    }

    @Override
    public Object getRequestAttribute(String key) {
        return requestAttributes.get(key);
    }

    @Override
    public void setRequestAttribute(String key, Object value) {
        requestAttributes.put(key, value);
    }

    @Override
    public void removeRequestAttribute(String key) {
        requestAttributes.remove(key);
    }


    @Override
    public void setApplicationAttribute(String key, Object value) {
        applicationAttributes.put(key, value);
    }

    @Override
    public Object getApplicationAttribute(String key) {
        Object value = applicationAttributes.get(key);
        if (value == null) {
            return authNBindings.getApplicationAttribute(key);
        } else {
            return value;
        }
    }

    @Override
    public void removeApplicationAttribute(String key) {
        applicationAttributes.remove(key);
    }


}
