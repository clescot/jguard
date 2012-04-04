/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2010  Charles Lescot
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

package net.sf.jguard.ext.authentication.manager;

import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import org.hibernate.cfg.Configuration;

import java.net.URL;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HibernateAuthenticationManagerModule extends AuthenticationManagerModule {
    public HibernateAuthenticationManagerModule(String applicationName, URL AuthenticationXmlFileLocation) {
        super(applicationName, AuthenticationXmlFileLocation, HibernateAuthenticationManager.class);
    }

    @Override
    protected void configure() {
        super.configure();
        Configuration configuration = new Configuration().configure();
        binder().bind(Configuration.class).toInstance(configuration);


    }


}
