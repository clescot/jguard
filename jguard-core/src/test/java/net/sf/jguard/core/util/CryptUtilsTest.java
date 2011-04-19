/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles GAY

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

import junit.framework.TestCase;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

public class CryptUtilsTest extends TestCase {

    /*
      * Test method for 'net.sf.jguard.ext.authentication.CryptUtils.cryptPassword(char[])'
      */
    public void testCryptPassword() {

        displayProvidersInformations();

        String password1 = "success";
        String md5FromPassword1ShouldBe = "260ca9dd8a4577fc00b7bd5810298076";
        String password2 = "guest";
        String md5FromPassword2ShouldBe = "084e0343a0486ff05530df6c705c8bb4";
//		String sha1fromPassword1ShouldBe="53a5687cb26dc41f2ab4033e97e13adefd3740d6";
        try {

            //test with no algorithm
            new String(CryptUtils.cryptPassword(password1.toCharArray()));
            assertEquals(password1, password1);

            //test with MD5 explicitly
            CryptUtils.setDigestAlgorithm("MD5");
            String result1 = new String(CryptUtils.cryptPassword(password1.toCharArray()));
            String result2 = new String(CryptUtils.cryptPassword(password2.toCharArray()));
            assertEquals(md5FromPassword1ShouldBe, result1);
            assertEquals(md5FromPassword2ShouldBe, result2);


        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
            fail();
        }

    }

    private void displayProvidersInformations() {
        List providers = Arrays.asList(Security.getProviders());
        for (Object provider : providers) {
            Provider prov = (Provider) provider;
            System.out.println(prov.getInfo());
        }
    }


}
