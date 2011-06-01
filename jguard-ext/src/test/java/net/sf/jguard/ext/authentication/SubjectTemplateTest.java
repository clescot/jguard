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
package net.sf.jguard.ext.authentication;

import javax.inject.Inject;
import com.google.inject.Module;
import com.mycila.testing.plugin.guice.ModuleProvider;
import junit.framework.TestCase;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.SubjectTemplate;
import net.sf.jguard.core.test.AuthenticationManagerTest;
import net.sf.jguard.ext.authentication.manager.XmlAuthenticationManager;
import org.junit.Test;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;

public class SubjectTemplateTest extends AuthenticationManagerTest {
    private SubjectTemplate st = null;
    @Inject
    private AuthenticationManager authenticationManager;
    /*
      * Test method for 'net.sf.jguard.ext.authentication.SubjectTemplate.validateUser(SubjectTemplate)'
      */

    @ModuleProvider
    public Iterable<Module> providesAuthenticationManagerModule() {
        List<Module> modules = new ArrayList<Module>();
        modules.add(new AuthenticationManagerModule(applicationName, authenticationXmlFileLocation, XmlAuthenticationManager.class));
        return modules;
    }

    @Test
    public void testValidateUser() {
        buildReferenceSubjectTemplate();
        SubjectTemplate st2 = new SubjectTemplate();
        Set<JGuardCredential> privateRequiredCredentails = new HashSet<JGuardCredential>();
        JGuardCredential j1 = new JGuardCredential("login", "azerty");
        privateRequiredCredentails.add(j1);
        JGuardCredential j2 = new JGuardCredential("password", "azerty");
        privateRequiredCredentails.add(j2);
        st2.setPrivateRequiredCredentials(privateRequiredCredentails);
        Set<JGuardCredential> publicRequiredCredentials = new HashSet<JGuardCredential>();
        JGuardCredential j3 = new JGuardCredential("location", "brest");
        publicRequiredCredentials.add(j3);
        st2.setPublicRequiredCredentials(publicRequiredCredentials);
        try {
            st.validateTemplate(st2);
        } catch (AuthenticationException e) {
            TestCase.fail(" user candidate does not validate against the reference userTemplate ");
        }

        SubjectTemplate st3 = new SubjectTemplate();
        try {
            st.validateTemplate(st3);
        } catch (AuthenticationException e) {
            e.printStackTrace();
            System.out.println(" test success => an exception is the normal result");
        }

    }


    /*
      * Test method for 'net.sf.jguard.ext.authentication.SubjectTemplate.buildSubject(SubjectTemplate, Set)'
      */
    @Test
    public void testBuildSubject() {
        buildReferenceSubjectTemplate();
        SubjectTemplate st2 = new SubjectTemplate();
        Set<Principal> principals = new HashSet<Principal>();
        Organization defaultOrganization = authenticationManager.getDefaultOrganization();
        principals.add(defaultOrganization);
        Subject subj = st.toSubject(st2, authenticationManager.getDefaultOrganization());
        assertEquals(principals, subj.getPrincipals());
    }

    public void buildReferenceSubjectTemplate() {
        st = new SubjectTemplate();
        Set<JGuardCredential> privateRequiredCred = new HashSet<JGuardCredential>();
        JGuardCredential j1 = new JGuardCredential("login", "");
        privateRequiredCred.add(j1);
        JGuardCredential j2 = new JGuardCredential("password", "");
        privateRequiredCred.add(j2);
        st.setPrivateRequiredCredentials(privateRequiredCred);
        Set<JGuardCredential> publicRequiredCred = new HashSet<JGuardCredential>();
        JGuardCredential j3 = new JGuardCredential("location", "");
        publicRequiredCred.add(j3);
        st.setPublicRequiredCredentials(publicRequiredCred);
        Set<JGuardCredential> publicOptionalCredentials = new HashSet<JGuardCredential>();
        JGuardCredential j4 = new JGuardCredential("hobbies", "");
        publicOptionalCredentials.add(j4);
        st.setPublicOptionalCredentials(publicOptionalCredentials);
        Set privateOptionalCredentials = new HashSet();
        st.setPrivateOptionalCredentials(privateOptionalCredentials);
    }

    @Test
    public void testClone() {
        SubjectTemplate st = new SubjectTemplate();
        try {
            SubjectTemplate st2 = (SubjectTemplate) st.clone();
            System.out.println(st2);
        } catch (CloneNotSupportedException e) {
            TestCase.fail(e.getMessage());
        }
    }
}
