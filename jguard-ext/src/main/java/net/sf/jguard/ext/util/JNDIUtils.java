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
package net.sf.jguard.ext.util;


import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchResult;


public class JNDIUtils {

    /**
     * grab the name in the namespace, and return the nth value in the naming hierarchy.
     *
     * @param result result found
     * @param level  level to be retrun from the result, to the root
     * @return value
     */
    public static String getValueInNameSpace(SearchResult result, int level) {
        String value = null;
        String nameSpace = result.getName();
        String[] tokens = nameSpace.split(",");
        String[] tok = tokens[level].split("=");
        value = tok[1];
        return value;

    }

    /**
     * prevent LDAP injection. method extracted from a CORSAIRE white paper.
     *
     * @param name
     * @return safe login
     */
    public static String escapeDn(String name) {
        // from RFC 2253 and the / character for JNDI
        final char[] META_CHARS = {'+', '"', '<', '>', ';', '/'};
        String escapedString = name;
        // BackSlash is both a Java and an LDAP escape character, so escape it first
        escapedString = escapedString.replaceAll("\\\\", "\\\\");

        // positional characters - see RFC 2253
        escapedString = escapedString.replaceAll("^#", "\\\\#");
        escapedString = escapedString.replaceAll("^ | $", "\\\\ ");

        for (char META_CHAR : META_CHARS) {
            escapedString = escapedString.replaceAll("\\" + META_CHAR, "\\\\" + META_CHAR);
        }
        return escapedString;
    }

    /**
     * prevent LDAP injection. method extracted from a CORSAIRE white paper.
     *
     * @param filterExpression
     * @return safe filterExpression
     */
    public static String escapeSearchFilter(String filterExpression) {
        // from RFC 2254
        String escapedString = filterExpression;
        escapedString = escapedString.replaceAll("\\\\", "\\\\5c");
        escapedString = escapedString.replaceAll("\\*", "\\\\2a");
        escapedString = escapedString.replaceAll("\\(", "\\\\28");
        escapedString = escapedString.replaceAll("\\)", "\\\\29");
        return escapedString;
    }


    /**
     * return as a String the attribute Value, and convert a byte[] into a new String.
     *
     * @param attribute attribute
     * @return attribute value
     * @throws NamingException
     */
    public static String getAttributeValue(Attribute attribute) throws NamingException {
        NamingEnumeration nameEnum = null;
        StringBuffer attributeValue = new StringBuffer();
        nameEnum = attribute.getAll();

        int i = 0;

        while (nameEnum.hasMore()) {
            if (i != 0) {
                attributeValue.append(",");
            }
            Object obj = nameEnum.next();
            if (obj instanceof byte[]) {
                byte[] bytes = (byte[]) obj;
                obj = new String(bytes);
            }

            attributeValue.append(obj.toString());
            i++;
        }

        nameEnum.close();

        return attributeValue.toString();
	}

	
}
