/*
 * jGuard is a security framework based on top of jaas (java authentication and authorization security).
 * it is written for web applications, to resolve simply, access control problems.
 * version $Name$
 * http://sourceforge.net/projects/jguard/
 *
 * Copyright (C) 2004-2011  Charles GAY
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

package net.sf.jguard.ext.log.logback;

import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;

/**
 * extends {@link PatternLayout} to add the pattern <b>jid</b> mapped to the JGuardCredentialConverter.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class JGuardEncoder extends PatternLayoutEncoder {


    private static final String JGUARD_CREDENTIAL_CONVERTER_PATTERN_ID = "jgc";
    private static final String JGUARD_ROLE_CONVERTER_PATTERN_ID = "jgr";


    @Override
    public void start() {
        PatternLayout patternLayout = new PatternLayout();
        patternLayout.getDefaultConverterMap().put(JGUARD_CREDENTIAL_CONVERTER_PATTERN_ID, JGuardCredentialConverter.class.getName());
        patternLayout.getDefaultConverterMap().put(JGUARD_ROLE_CONVERTER_PATTERN_ID, RolesConverter.class.getName());
        patternLayout.setContext(context);
        patternLayout.setPattern(getPattern());
        patternLayout.start();
        this.layout = patternLayout;
        super.start();
    }

}
