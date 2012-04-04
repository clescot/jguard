/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
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
package net.sf.jguard.core.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.io.File;
import java.net.URI;

/**
 * Utility class to grab files with location as an URI containing a <i>'file'</i> protocol
 * or as a <i>JNDI</i> location.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public final class FileUtils {

    private static final String FILE = "file";
    private static final Logger logger = LoggerFactory.getLogger(FileUtils.class.getName());


    private FileUtils() {

    }

    public static File getFile(URI uri) {
        File file = null;
        if (uri.getScheme().equals(FileUtils.FILE)) {
            file = new File(uri);
        } else {
            Context initContext;
            try {
                initContext = new InitialContext();
                file = (File) initContext.lookup(uri.toString());
            } catch (NamingException e) {
                logger.warn(" file cannot be found : \nthe uri (" + uri.toString() + ") pointing to it does not contains a 'file' scheme protocol or does not point to a JNDI object bound ");
                logger.warn(e.getMessage());
            }

        }
        return file;
    }


}
