/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2010  Charles GAY
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

package net.sf.jguard.core.jmx;

import com.google.inject.AbstractModule;

import javax.management.MBeanServer;
import javax.management.remote.JMXAuthenticator;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXServiceURL;
import java.rmi.registry.Registry;

public class JMXModule extends AbstractModule {
    private String rmiRegistryHost;
    private int rmiRegistryPort;

    public JMXModule(String rmiRegistryHost, int rmiRegistryPort) {
        this.rmiRegistryHost = rmiRegistryHost;
        this.rmiRegistryPort = rmiRegistryPort;
    }

    @Override
    protected void configure() {
        bind(Registry.class).toProvider(RegistryProvider.class);
        bind(String.class).annotatedWith(RmiRegistryHost.class).toInstance(rmiRegistryHost);
        bind(Integer.class).annotatedWith(RmiRegistryPort.class).toInstance(rmiRegistryPort);
        bind(JMXServiceURL.class).toProvider(JMXServiceURLProvider.class);
        bind(MBeanServer.class).toProvider(MBeanServerProvider.class);
        bind(JMXAuthenticator.class).toProvider(JMXAuthenticatorProvider.class);
        bind(JMXConnectorServer.class).toProvider(JMXConnectorServerProvider.class);
    }
}
