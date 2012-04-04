/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.

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
package net.sf.jguard.core.authorization.permissions;

import junit.framework.TestCase;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net ">Charles Lescot</a>
 */
public class URLPermissionTest {
    private static URLPermission url1;
    private static URLPermission url1bis;
    private static URLPermission url2;
    private static URLPermission url3;
    private static URLPermission url4;
    private static URLPermission url5;
    private static URLPermission url8;
    private static URLPermission url9;
    private static URLPermission url9bis;
    private static URLPermission url10;
    private static URLPermission url11;
    private static URLPermission url12;
    private static URLPermission url13;
    private static URLPermission url13empty;
    private static URLPermission url14;
    private static URLPermission url15;
    private static URLPermission url16;
    private static URLPermission url17;
    private static URLPermission url18;
    private static URLPermission url19;
    private static URLPermission url20;

    private static URLPermission url21;
    private static URLPermission url22;
    private static URLPermission url23;
    private static URLPermission url24;
    private static URLPermission url25;
    private static URLPermission url26;
    private static URLPermission url27;
    private static URLPermission url28;
    private static URLPermission url29;
    private static URLPermission url30;
    private static URLPermission url31;
    private static URLPermission url32;
    private static final String DUMMY_PERMISSION_NAME = "dummyPermissionName";


    /**
     * @see TestCase#setUp()
     */
    @BeforeClass
    public static void setUp() throws Exception {
        StringBuffer actions1 = new StringBuffer();
        actions1.append("http://blabla.com/path1?param1=a&param2=b");
        actions1.append(",,");
        actions1.append("description1");
        url1 = new URLPermission("url1", actions1.toString());

        StringBuffer actions1bis = new StringBuffer();
        actions1bis.append("http://blabla.com/path1?param1=a&param2=b");
        actions1bis.append(",,");
        actions1bis.append("description1");
        url1bis = new URLPermission("url1", actions1bis.toString());

        StringBuffer actions2 = new StringBuffer();
        actions2.append("http://blabla.com/path1?param1=a&param2=b");
        actions2.append(",,");
        actions2.append("description2");
        url2 = new URLPermission("url2", actions2.toString());

        StringBuffer actions3 = new StringBuffer();
        actions3.append("http://blabla.com/path1");
        actions3.append(",,");
        actions3.append("description3");
        url3 = new URLPermission("url3", actions3.toString());

        StringBuffer actions4 = new StringBuffer();
        actions4.append("http://blabla.com/path1");
        actions4.append(",,");
        actions4.append("description4");
        url4 = new URLPermission("url4", actions4.toString());

        StringBuffer actions5 = new StringBuffer();
        actions5.append("http://blabla.com/path5?param1=a&param2=b");
        actions5.append(",,");
        actions5.append("description5");
        url5 = new URLPermission("url5", actions5.toString());

        StringBuffer actions6 = new StringBuffer();
        actions6.append("http://blabla.com/path6 blabla");
        actions6.append(",,");
        actions6.append("description6");
        try {
            new URLPermission("url6", actions6.toString());
        } catch (IllegalArgumentException iae) {
            System.out.println(" exception is the normal case");
        }
        StringBuffer actions7 = new StringBuffer();
        actions7.append("http://blabla.com/path7%20blabla");
        actions7.append(",,");
        actions7.append("description7");
        new URLPermission("url7", actions7.toString());

        StringBuffer actions8 = new StringBuffer();
        actions8.append("http://blabla.com/testeBotao");
        actions8.append(",,");
        actions8.append("description8");
        url8 = new URLPermission("url8", actions8.toString());

        StringBuffer actions9 = new StringBuffer();
        actions9.append("http://blabla.com/testeBotaoxxx");
        actions9.append(",,");
        actions9.append("description9");
        url9 = new URLPermission("url9", actions9.toString());


        StringBuffer actions9bis = new StringBuffer();
        actions9bis.append("/Logon.do|/Captcha.do");
        actions9bis.append(",,");
        actions9bis.append("description9");
        url9bis = new URLPermission("url9bis", actions9bis.toString());


        StringBuffer actions10 = new StringBuffer();
        actions10.append("http://blabla.com/testeBotao*");
        actions10.append(",,");
        actions10.append("description10");
        url10 = new URLPermission("url10", actions10.toString());

        StringBuffer actions11 = new StringBuffer();
        actions11.append("http://blabla.com/tes*aoxxx");
        actions11.append(",,");
        actions11.append("description11");
        url11 = new URLPermission("url11", actions11.toString());

        StringBuffer actions12 = new StringBuffer();
        actions12.append("/path1?param1=a&param2=b");
        actions12.append(",,");
        actions12.append("description12");
        url12 = new URLPermission("url12", actions12.toString());

        StringBuffer actions13 = new StringBuffer();
        actions13.append("/path1?param1=a&param2=b");
        actions13.append(",,");
        actions13.append("description13");
        url13 = new URLPermission("url13", actions13.toString());

        url13empty = new URLPermission("url13");

        url14 = new URLPermission("url14");
        //url14.setUri(new URI("/toto.do"));


        StringBuffer actions15 = new StringBuffer();
        actions15.append("/index.html");
        actions15.append(",,");
        actions15.append("description15");
        url15 = new URLPermission("url15", actions15.toString());

        StringBuffer actions16 = new StringBuffer();
        actions16.append("/*");
        actions16.append(",,");
        actions16.append("description16");
        url16 = new URLPermission("url16", actions16.toString());

        StringBuffer actions17 = new StringBuffer();
        actions17.append("http://blabla.com/path?param1='a'");
        actions17.append(",,");
        actions17.append("");
        url17 = new URLPermission("url17", actions17.toString());

        StringBuffer actions18 = new StringBuffer();
        actions18.append("http://blabla.com/path?param1='b'");
        actions18.append(",,");
        actions18.append("");
        url18 = new URLPermission("url18", actions18.toString());

        StringBuffer actions19 = new StringBuffer();
        actions19.append("http://blabla.com/*?param1='a'");
        actions19.append(",,");
        actions19.append("");
        url19 = new URLPermission("url19", actions19.toString());

        StringBuffer actions20 = new StringBuffer();
        actions20.append("http://blabla.com/path");
        actions20.append(",,");
        actions20.append("");
        url20 = new URLPermission("url20", actions20.toString());

        // tests for parameter evaluations
        StringBuffer actions21 = new StringBuffer();
        actions21.append("http://blabla.com/path?param1=abc&param2=b");
        actions21.append(",,");
        actions21.append("");
        url21 = new URLPermission("url21", actions21.toString());

        StringBuffer actions22 = new StringBuffer();
        actions22.append("http://blabla.com/path?param1=abc&*");
        actions22.append(",,");
        actions22.append("");
        url22 = new URLPermission("url22", actions22.toString());

        StringBuffer actions23 = new StringBuffer();
        actions23.append("http://blabla.com/path?param1=abc&param2=*");
        actions23.append(",,");
        actions23.append("");
        url23 = new URLPermission("url23", actions23.toString());

        StringBuffer actions24 = new StringBuffer();
        actions24.append("http://blabla.com/path?param1=*");
        actions24.append(",,");
        actions24.append("");
        url24 = new URLPermission("url24", actions24.toString());

        StringBuffer actions25 = new StringBuffer();
        actions25.append("http://blabla.com/path?param1=a*&*");
        actions25.append(",,");
        actions25.append("");
        url25 = new URLPermission("url25", actions25.toString());

        StringBuffer actions26 = new StringBuffer();
        actions26.append("http://blabla.com/path?param1=dce&*");
        actions26.append(",,");
        actions26.append("");
        url26 = new URLPermission("url26", actions26.toString());

        // param with empty value
        StringBuffer actions27 = new StringBuffer();
        actions27.append("http://blabla.com/path?param1=dce&param2=&param3=2");
        actions27.append(",,");
        actions27.append("");
        url27 = new URLPermission("url27", actions27.toString());

        StringBuffer actions28 = new StringBuffer();
        actions28.append("http://blabla.com/path1?param1=a&param2=b");
        actions28.append(",https,");
        actions28.append("description1");
        url28 = new URLPermission("url28", actions28.toString());

        StringBuffer actions29 = new StringBuffer();
        actions29.append("http://blabla.com/path1?param1=a&param2=b");
        actions29.append(",https");
        actions29.append(",GET");
        actions29.append(",description1");
        url29 = new URLPermission("url29", actions29.toString());


        StringBuffer actions30 = new StringBuffer();
        actions30.append("http://blabla.com/path1?param1=a&param2=b");
        actions30.append(",https");
        actions30.append(",TRACE");
        actions30.append(",description1");
        url30 = new URLPermission("url30", actions30.toString());


        StringBuffer actions31 = new StringBuffer();
        actions31.append("http://blabla.com/path1?param1=a&param2=b");
        actions31.append(",https");
        actions31.append(",ANY");
        actions31.append(",description1");
        url31 = new URLPermission("url31", actions31.toString());

        StringBuffer actions32 = new StringBuffer();
        actions32.append("http://blabla.com/path1?param1=a&param2=b");
        actions32.append(",https");
        actions32.append(",GET");
        actions32.append(",description1");
        url32 = new URLPermission("url32", actions32.toString());

    }


    /**
     * Class under test for boolean implies(java.security.Permission)
     */
    @Test
    public void testImpliesPermission() {
        //two urlPermissions with differents name but the same url
        //implies
        assertTrue(url1.implies(url1));
        assertTrue(url1.implies(url2));
        assertTrue(url3.implies(url4));
        assertTrue(url3.implies(url2));
        assertFalse(url2.implies(url3));
        assertFalse(url5.implies(url3));
        assertFalse(url5.implies(url2));
        assertFalse(url8.implies(url9));
        assertTrue(url10.implies(url9));
        assertTrue(url11.implies(url9));
        assertFalse(url1.implies(url12));
        assertTrue(url12.implies(url13));

        assertTrue(url16.implies(url15));

        assertFalse(url17.implies(url18));

        assertTrue(url19.implies(url17));
        assertFalse(url19.implies(url18));

        assertTrue(url20.implies(url17));
        assertFalse(url17.implies(url20));

        assertTrue(url22.implies(url21));
        assertTrue(url23.implies(url21));
        assertFalse(url24.implies(url21));
        assertTrue(url25.implies(url21));
        assertFalse(url26.implies(url21));
        assertTrue(url26.implies(url27));
        assertTrue(url28.implies(url29));
        assertFalse(url29.implies(url28));
        assertFalse(url29.implies(url30));
        assertFalse(url30.implies(url31));
        assertTrue(url31.implies(url30));
        assertTrue(url31.implies(url32));
        assertFalse(url32.implies(url31));

        assertTrue(url9bis.implies(new URLPermission("toto", "/Captcha.do")));
        assertTrue(url9bis.implies(new URLPermission("toto", "/Logon.do")));
    }

    /**
     * Class under test for boolean implies(java.security.Permission)
     */
    @Test
    public void testEquals() {

        assertFalse(url1.equals(url2));
        assertTrue(url1.equals(url1bis));
        assertTrue(url1bis.equals(url1));
        assertFalse(url3.equals(url4));
        assertFalse(url13.equals(url13empty));
        assertFalse(url14.equals(url13));
        assertFalse(url1.equals(url28));
    }

    @Test
    public void testRemoveRegexpFromURI() {
        //method should remove all isolated star
        List<String> patterns = new ArrayList<String>();
        patterns.add("/teest*.do?toto=4&titi=dfgdfg");
        patterns.add("/tee*st.do?toto=4&titi=dfgdfg");
        patterns.add("/t*eest.do?toto=4&titi=dfgdfg");
        patterns.add("/t*ees*t.do?toto=4&titi=dfgdfg");
        patterns.add("/t*ees*t.do*?toto=4&titi=dfgdfg");
        patterns.add("/t*ees*t.do*?toto=4&titi=dfgdfg");
        patterns.add("/teest.do?toto=4&titi=dfgdfg");
        System.out.println("******************");
        for (String pattern1 : patterns) {
            try {
                System.out.println("prettyPattern=" + pattern1);
                String uri = URLPermission.removeRegexpFromURI(pattern1);

                System.out.println("uri=" + uri);
                assertFalse(uri.matches("\\*"));
            } catch (Throwable e) {
                TestCase.fail(e.getMessage());
            }
        }

        //method should remove only one star
        String pattern = "/tee**st.do?toto=4&titi=dfgdfg";
        System.out.println("prettyPattern=" + pattern);
        try {
            String path = URLPermission.removeRegexpFromURI(pattern);
            System.out.println("path=" + path);
            assertTrue(path.equals("/tee*st.do?toto=4&titi=dfgdfg"));
        } catch (Throwable e) {
            TestCase.fail(e.getMessage());
        }

        //method should remove only one star
        String pattern2 = "/tee****st.do?toto=4&titi=dfgdfg";
        System.out.println("prettyPattern=" + pattern);
        try {
            String path = URLPermission.removeRegexpFromURI(pattern2);

            System.out.println("path=" + path);
            assertTrue(path.equals("/tee**st.do?toto=4&titi=dfgdfg"));
        } catch (Throwable e) {
            TestCase.fail(e.getMessage());
        }


    }

    @Test
    public void testCompareTo() {
        URLPermission up1 = new URLPermission("hello");
        URLPermission up2 = new URLPermission("zoo");
        URLPermission up3 = new URLPermission("zoo");
        URLPermission up4 = new URLPermission("zoo", "toto");
        URLPermission up5 = new URLPermission("zoo", "titi");
        URLPermission up6 = new URLPermission("zoo", "titisdfsd");
        assertTrue(up1.compareTo(up2) < 1);
        assertTrue(up2.compareTo(up1) > 1);
        assertTrue(up3.compareTo(up2) == 0);
        assertTrue(up2.compareTo(up3) == 0);
        assertTrue(up4.compareTo(up5) == 0);
        assertTrue(up5.compareTo(up4) == 0);
        assertTrue(up4.compareTo(up6) == 0);
        assertTrue(up6.compareTo(up4) == 0);
    }

    /**
     * verifies that a URI is returned, and that regexp has been removed.
     */
    @Test
    public void testGetURI() {
        String urlWithoutRegexp = "http://blabla.com/path";
        String urlWithRegexp = "http://blabla.com/path*";
        URLPermission permission = new URLPermission(DUMMY_PERMISSION_NAME, urlWithRegexp);
        assertTrue(permission.getURI() != null);
        assertEquals(urlWithoutRegexp, permission.getURI());
    }

    @Test
    public void testURLPermissionWith5Actions(){
        URLPermission permission = new URLPermission("name","action1,action2,action3,action4,action5");
    }


    @Test(expected = IllegalArgumentException.class)
    public void testURLPermissionWith6Actions(){
        URLPermission permission = new URLPermission("name","action1,action2,action3,action4,action5,action6");
    }

}
