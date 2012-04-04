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
package net.sf.jguard.ext.util;

import junit.framework.Assert;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandlerProvider;
import net.sf.jguard.core.util.XMLUtils;
import org.dom4j.Document;
import org.dom4j.Element;
import org.junit.Test;
import org.xml.sax.InputSource;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

import static org.junit.Assert.assertTrue;

public class XMLUtilsTest {


    /*
    * Test method for 'net.sf.jguard.ext.util.XMLUtils.read(String)'
    */
    @Test
    public void testRead() {

        Document doc;
        URL url = getClass().getResource("/jGuardUsersPrincipals.xml");
        String strUrl = url.toString();
        Element root;
        InputSource inputSource;
        URL schemaUrl = null;
        try {
            schemaUrl = Thread.currentThread().getContextClassLoader().getResource("jGuardUsersPrincipals_2.0.0.xsd");
            inputSource = getInputSource(schemaUrl);
            String res = XMLUtils.resolveLocation(strUrl);
            doc = XMLUtils.read(new URL(res), inputSource);
            root = doc.getRootElement();
            assertTrue(" there is no elements in the document ", root.elements().size() > 0);
        } catch (Throwable e) {
            Assert.fail(" testRead fail ");
        }

        try {
            String str1 = strUrl.replaceFirst("file:///", "file:/");
            System.out.println("str1=" + str1);
            inputSource = getInputSource(schemaUrl);
            String res1 = XMLUtils.resolveLocation(str1);
            doc = XMLUtils.read(new URL(res1), inputSource);
            root = doc.getRootElement();
            assertTrue(" there is no elements in the document ", root.elements().size() > 0);
        } catch (Throwable e) {
            Assert.fail(" testRead fail ");
        }

        try {
            String str2 = strUrl.replaceFirst("file:///", "file://");
            System.out.println("str2=" + str2);
            inputSource = getInputSource(schemaUrl);
            String res2 = XMLUtils.resolveLocation(str2);
            doc = XMLUtils.read(new URL(res2), inputSource);
            root = doc.getRootElement();
            assertTrue(" there is no elements in the document ", root.elements().size() > 0);
        } catch (Throwable e) {
            Assert.fail(" testRead fail ");
        }
        try {
            String str3 = strUrl.replaceFirst("file:///", "file://///////////");
            System.out.println("str3=" + str3);
            inputSource = getInputSource(schemaUrl);
            String res3 = XMLUtils.resolveLocation(str3);
            doc = XMLUtils.read(new URL(res3), inputSource);
            root = doc.getRootElement();
            assertTrue(" there is no elements in the document ", root.elements().size() > 0);
        } catch (Throwable e) {
            Assert.fail(" testRead fail ");
        }

        try {
            String str4 = strUrl.replaceFirst("file:///", "file:///////qsdfsdf");
            System.out.println("str4=" + str4);
            inputSource = getInputSource(schemaUrl);
            String res4 = XMLUtils.resolveLocation(str4);
            doc = XMLUtils.read(new URL(res4), inputSource);
            root = doc.getRootElement();
            assertTrue(" there is no elements in the document ", root.elements().size() > 0);
        } catch (Throwable e) {
            Assert.fail(" testRead fail ");
        }


    }

    private InputSource getInputSource(URL schemaUrl) throws FileNotFoundException, URISyntaxException {
        FileReader fileReader = new FileReader(new File(schemaUrl.toURI()));
        return new InputSource(fileReader);
    }

    @Test
    public void testResolveLocation() throws URISyntaxException, MalformedURLException {
        String[] filePatterns = {"file:/toto", "file://toto", "file:///toto",
                "file:////toto", "file://///toto", "file://///toto",
                "file:////////toto"};

        String[] blankPatterns = {"file:////to to", "file:////to to ",
                "file:////toto%20toto "};
        String[] antiSlashAndBlankPattern = {"file:///C:\\Program Files\\Apache Software Foundation\\Tomcat6.0\\webapps\\modul_curier\\WEB-INF\\jGuard\\jGuardUsersPrincipals.xml"};

        testPatterns(filePatterns);
        testPatterns(blankPatterns);
        testPatterns(antiSlashAndBlankPattern);
    }


    private void testPatterns(String[] patterns) {
        for (String pattern : patterns) {
            String resolvedPattern = XMLUtils.resolveLocation(pattern);
            System.out.println("*" + resolvedPattern + "*");
            try {
                URL url = new URL(resolvedPattern);
            } catch (MalformedURLException e) {
                Assert.fail(e.getLocalizedMessage());
            }
        }
    }

    @Test
    public void testReadjGuardAuthenticationWithJcaptcha() throws MalformedURLException {

        Document doc;
        URL url = Thread.currentThread().getContextClassLoader().getResource("JguardFilterWithJcaptcha.xml");
        assertTrue("le document jGuardAuthenticationWithJcaptcha cannot be reached", url != null);
        Element root;


        try {
            URL schemaUrl = Thread.currentThread().getContextClassLoader().getResource("jGuardFilter_2.0.0.xsd");
            FileReader fileReader = new FileReader(new File(schemaUrl.toURI()));
            InputSource inputSource = new InputSource(fileReader);
            doc = XMLUtils.read(url, inputSource);
            root = doc.getRootElement();
            assertTrue(" document cannot be read", root.element(AuthenticationSchemeHandlerProvider.AUTHENTICATION_SCHEME_HANDLER) != null);
        } catch (Throwable e) {
            Assert.fail(" testRead fail " + e.getMessage());
        }
    }

}
