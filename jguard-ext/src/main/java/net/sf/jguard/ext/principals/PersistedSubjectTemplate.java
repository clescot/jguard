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
package net.sf.jguard.ext.principals;

import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.principals.SubjectTemplate;
import org.hibernate.Session;

import javax.inject.Provider;
import java.io.Serializable;
import java.security.Principal;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class PersistedSubjectTemplate implements Serializable {
    private Long id;
    private Set<? extends Principal> principals;

    private Set<SubjectTemplateCredential> subjectTemplateCredentials;

    public PersistedSubjectTemplate() {
        subjectTemplateCredentials = new HashSet<SubjectTemplateCredential>();
        principals = new HashSet<Principal>();
    }

    public PersistedSubjectTemplate(SubjectTemplate subjectTemplate, Provider<Session> sessionProvider) {
        super();
        id = subjectTemplate.getId();
        subjectTemplateCredentials = new HashSet<SubjectTemplateCredential>();
        addCredentialSet(subjectTemplate.getPrivateRequiredCredentials(), false, true);
        addCredentialSet(subjectTemplate.getPublicRequiredCredentials(), true, true);
        addCredentialSet(subjectTemplate.getPublicOptionalCredentials(), true, false);
        addCredentialSet(subjectTemplate.getPrivateOptionalCredentials(), false, false);

        principals = new HibernatePrincipalUtils(sessionProvider).getPersistedPrincipals(subjectTemplate.getPrincipals());
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Set<? extends Principal> getPrincipals() {
        return principals;
    }

    public void setPrincipals(Set<Principal> principals) {
        this.principals = principals;
    }

    public Set<JGuardCredential> getPublicOptionalCredentials() {
        return getSubjectTemplateCredentials(true, false);
    }

    public Set<JGuardCredential> getPublicRequiredCredentials() {
        return getSubjectTemplateCredentials(true, true);
    }

    public Set<JGuardCredential> getPrivateRequiredCredentials() {
        return getSubjectTemplateCredentials(false, true);
    }

    public Set<JGuardCredential> getPrivateOptionalCredentials() {
        return getSubjectTemplateCredentials(false, false);
    }

    public Set<SubjectTemplateCredential> getSubjectTemplateCredentials() {
        return subjectTemplateCredentials;
    }

    private Set<JGuardCredential> getSubjectTemplateCredentials(boolean publicVisibility, boolean required) {
        Set<JGuardCredential> credentials = new HashSet<JGuardCredential>();
        for (SubjectTemplateCredential stc : getSubjectTemplateCredentials()) {
            if (stc.isPublicVisibility() == publicVisibility && stc.isRequired() == required) {
                credentials.add(stc.getCredential());
            }
        }
        return credentials;
    }

    public void setSubjectTemplateCredentials(Set<SubjectTemplateCredential> subjectTemplateCredentials) {
        this.subjectTemplateCredentials = subjectTemplateCredentials;
    }

    public void setPublicOptionalCredentials(Set publicOptionalCredentials) {
        addCredentialSet(publicOptionalCredentials, true, false);
    }

    public void setPublicRequiredCredentials(Set publicOptionalCredentials) {
        addCredentialSet(publicOptionalCredentials, true, true);
    }

    public void setPrivateRequiredCredentials(Set publicOptionalCredentials) {
        addCredentialSet(publicOptionalCredentials, false, true);
    }

    public void setPrivateOptionalCredentials(Set publicOptionalCredentials) {
        addCredentialSet(publicOptionalCredentials, false, false);
    }

    private void addCredentialSet(Set creds, boolean publicVisibility, boolean required) {

        //remove similar credentials
        Iterator itStc = getSubjectTemplateCredentials().iterator();
        while (itStc.hasNext()) {
            SubjectTemplateCredential stc = (SubjectTemplateCredential) itStc.next();
            if (stc.isPublicVisibility() == publicVisibility && stc.isRequired() == required) {
                itStc.remove();
            }
        }

        for (Object next : creds) {
            if (next instanceof JGuardCredential) {
                JGuardCredential cred = (JGuardCredential) next;
                SubjectTemplateCredential stc = new SubjectTemplateCredential(this, cred, publicVisibility, required);
                getSubjectTemplateCredentials().add(stc);
            }
        }
    }

    public SubjectTemplate toSubjectTemplate() {
        SubjectTemplate st = new SubjectTemplate();
        st.setId(id);
        st.setPrincipals(HibernatePrincipalUtils.getjavaSecurityPrincipals((Set<PersistedPrincipal>) st.getPrincipals()));
        st.setPrivateOptionalCredentials(getPrivateOptionalCredentials());
        st.setPrivateRequiredCredentials(getPrivateRequiredCredentials());
        st.setPublicOptionalCredentials(getPublicOptionalCredentials());
        st.setPublicRequiredCredentials(getPublicRequiredCredentials());
        return st;
    }
}
