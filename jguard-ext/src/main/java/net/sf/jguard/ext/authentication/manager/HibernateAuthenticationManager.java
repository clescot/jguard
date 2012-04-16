/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
package net.sf.jguard.ext.authentication.manager;

import com.google.inject.Provider;
import net.sf.jguard.core.ApplicationName;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.manager.AbstractAuthenticationManager;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authentication.manager.AuthenticationXmlStoreFileLocation;
import net.sf.jguard.core.principals.Organization;
import net.sf.jguard.core.principals.OrganizationTemplate;
import net.sf.jguard.core.util.SubjectUtils;
import net.sf.jguard.core.util.XMLUtils;
import net.sf.jguard.ext.principals.HibernatePrincipalUtils;
import net.sf.jguard.ext.principals.PersistedOrganization;
import net.sf.jguard.ext.principals.PersistedPrincipal;
import net.sf.jguard.ext.principals.PersistedSubject;
import org.hibernate.*;
import org.hibernate.criterion.Example;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.Subject;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.util.*;

/**
 * Hibernate AuthenticationManager implementation.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HibernateAuthenticationManager extends AbstractAuthenticationManager {

    private static Logger logger = LoggerFactory.getLogger(HibernateAuthenticationManager.class.getName());
    private static final String LOGIN = "login";
    private static final String ACTIVE = "active";
    private static final String NAME = "name";
    private static final String VALUE = "value";
    private static final String SELECT_ORGA_TEMPLATE = " select orga from net.sf.jguard.ext.principals.PersistedOrganization as orga inner join orga.credentials as creds where creds.name='id' and creds.value='template' ";
    private static final String J_GUARD_USERS_PRINCIPALS_XML = "/" + "jGuardUsersPrincipals.xml";
    private static final char SLASH = '/';
    private Provider<Session> sessionProvider;

    @Inject
    public HibernateAuthenticationManager(@ApplicationName String applicationName,
                                          @AuthenticationXmlStoreFileLocation URL authenticationXmlFileLocation,
                                          Provider<Session> sessionProvider) {
        super(applicationName);
        this.sessionProvider = sessionProvider;

        Transaction tx = null;
        try {
            tx = sessionProvider.get().beginTransaction();
            if (isEmpty()) {
                importXmlData(authenticationXmlFileLocation);
            }
            tx.commit();
        } catch (Exception ex) {
            if (tx != null) tx.rollback();
            throw new RuntimeException(ex);
        } finally {
            if (sessionProvider.get() != null && sessionProvider.get().isOpen()) {
                sessionProvider.get().close();
            }
        }


    }

    private void importXmlData(URL dbPropertiesLocation) {

        if (dbPropertiesLocation == null) {
            throw new IllegalArgumentException(AUTHENTICATION_XML_FILE_LOCATION + " parameter =null");
        }
        String dbPath;
        try {
            dbPath = XMLUtils.resolveLocation(dbPropertiesLocation.toURI().toString());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }


        String xmlFileLocation = dbPath.substring(0, dbPath.lastIndexOf(SLASH)) + J_GUARD_USERS_PRINCIPALS_XML;
        URL url;
        try {
            url = new URL(XMLUtils.resolveLocation(xmlFileLocation));
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        AuthenticationManager authentManager = new XmlAuthenticationManager(applicationName, url);
        importAuthenticationManager(authentManager);

    }


    protected void persistUser(Subject user) throws AuthenticationException {

        PersistedOrganization pOrga = getPersistedOrganizationFromSubject(user);
        PersistedSubject persistedSubject = new PersistedSubject(user, pOrga, sessionProvider);
        sessionProvider.get().saveOrUpdate(persistedSubject);
        if (persistedSubject.getId() != null && !persistedSubject.getId().toString().equals("0")) {
            //this credential is used to keep track of the database row in an Object not related with datéabase in its API
            JGuardCredential persistanceIdCredential = new JGuardCredential(PersistedSubject.PERSISTENCE_ID, persistedSubject.getId().toString());
            user.getPrivateCredentials().add(persistanceIdCredential);
        }
        user = persistedSubject.toJavaxSecuritySubject();
    }

    protected void persistPrincipal(Principal principal) throws AuthenticationException {

        PersistedPrincipal ppal = new HibernatePrincipalUtils(sessionProvider).getPersistedPrincipal(principal);
        if (ppal != null) {
            sessionProvider.get().saveOrUpdate(ppal);
        }

    }

    protected void persistOrganization(Organization organization) throws AuthenticationException {
        PersistedOrganization orga;
        orga = new PersistedOrganization(organization, sessionProvider);

        sessionProvider.get().saveOrUpdate(orga);
        organization.setId(orga.getId());

    }

    protected void updateUserImpl(JGuardCredential identityCred, Subject user) throws AuthenticationException {

        //check old identityCred
        checkCredential(identityCred);

        //check new identityCred
        JGuardCredential newIdentityCredential = getIdentityCredential(user);
        checkCredential(newIdentityCredential);

        //find user stored in database with the same identity cred
        PersistedSubject foundUser = findPersistedUser((String) identityCred.getValue());
        PersistedOrganization persistedOrganization = foundUser.getOrganization();
        //we check that organisation of the updatedUSer map to the persistedUser
        if (!persistedOrganization.toOrganization().equals(SubjectUtils.getOrganization(user))) {
            throw new IllegalStateException("user " + user + " has got an organization different" + SubjectUtils.getOrganization(user) + " from the user stored in database" + persistedOrganization.toOrganization());
        }

        //we update the stored user with the user modified
        foundUser.update(user);
        Session session = sessionProvider.get();
        session.update(foundUser);
    }

    private void checkCredential(JGuardCredential identityCred) {
        if (identityCred == null || identityCred.getName() == null || identityCred.getValue() == null) {
            throw new IllegalArgumentException("an identity credential is null, or has got a name or value null " + identityCred);
        }
    }

    public Set findUsers(Collection<JGuardCredential> privateCredentials, Collection<JGuardCredential> publicCredentials) throws AuthenticationException {
        Set usersFound = new HashSet();

        //use public credentials
        for (JGuardCredential cred : privateCredentials) {
            Set users = findUsers(cred, true);
            if (usersFound.size() > 0) {
                usersFound.retainAll(users);
            } else {
                usersFound.addAll(users);
            }
        }

        //use private credentials
        for (JGuardCredential cred : publicCredentials) {
            Set users = findUsers(cred, false);
            usersFound.addAll(users);
        }

        return usersFound;
    }

    private Set findUsers(JGuardCredential cred, boolean priv) {
        String q = " select subject from net.sf.jguard.ext.principals.PersistedSubject as subject ";
        if (cred.getName().equals(LOGIN) || cred.getName().equals(ACTIVE)) {
            q += "  where subject." + cred.getName() + "= :" + cred.getName();
        } else {
            if (priv) {
                q += " inner join subject.privateCredentials as cred ";
            } else {
                q += " inner join subject.publicCredentials as cred ";
            }

            q += " where cred.name= :name and cred.value= :value ";
        }


        Query query = sessionProvider.get().createQuery(q);

        if (cred.getName().equals(LOGIN)) {
            query.setString(cred.getName(), cred.getValue().toString());
        } else if (cred.getName().equals(ACTIVE)) {
            query.setBoolean(cred.getName(), Boolean.valueOf(cred.getValue().toString()));
        } else {
            query.setString(NAME, cred.getName());
            query.setString(VALUE, cred.getValue().toString());
        }
        List results = query.list();
        return new HashSet(results);

    }

    public Subject findUser(String login) {

        PersistedSubject result = findPersistedUser(login);
        if (result == null) return null;
        Set<PersistedSubject> set = new HashSet<PersistedSubject>();
        set.add(result);
        Set<Subject> s = getJavaxSecuritySubjects(set);
        Iterator<Subject> it = s.iterator();
        return it.next();
    }

    private PersistedSubject findPersistedUser(String login) {
        final String QUERY = " select subject from net.sf.jguard.ext.principals.PersistedSubject as subject  where subject.login=:login ";
        Session session = sessionProvider.get();
        Query query = session.createQuery(QUERY);
        query.setString(LOGIN, login);
        PersistedSubject result = (PersistedSubject) query.uniqueResult();
        if (result == null) {
            return null;
        }
        return result;
    }

    public Set<Subject> getUsers() throws AuthenticationException {
        Criteria criteria = sessionProvider.get().createCriteria(PersistedSubject.class);
        List<PersistedSubject> usersList = criteria.list();
        Set<PersistedSubject> users = new HashSet<PersistedSubject>(usersList);
        return getJavaxSecuritySubjects(users);
    }

    public Collection<Organization> findOrganizations(Collection<JGuardCredential> credentials) throws AuthenticationException {
        Criteria criteria = sessionProvider.get().createCriteria(PersistedSubject.class);
        Organization org = new Organization();
        org.setCredentials(new HashSet<JGuardCredential>(credentials));
        Example example = Example.create(org);
        criteria.add(example);
        List results = criteria.list();
        return new HashSet<Organization>(results);
    }

    public void deleteOrganization(Organization organization) {
        sessionProvider.get().delete(organization);
    }

    public Set<Organization> getOrganizations() throws AuthenticationException {
        Query query = sessionProvider.get().createQuery(SELECT_ORGA_TEMPLATE);
        List<PersistedOrganization> organizationsList = query.list();
        Set<PersistedOrganization> orgas = new HashSet<PersistedOrganization>(organizationsList);
        return HibernatePrincipalUtils.getOrganizations(orgas);

    }

    public void updateOrganization(String organizationIdentityCredential, Organization organization) throws AuthenticationException {

        PersistedOrganization pOrg = findPersistedOrganization(organization.getName());
        sessionProvider.get().update(pOrg);

    }

    public Organization findOrganization(String organizationName) {
        PersistedOrganization persistedOrganization = findPersistedOrganization(organizationName);
        Organization orga = null;
        if (persistedOrganization != null) {
            orga = persistedOrganization.toOrganization();
        }

        return orga;
    }

    public Set<Principal> getAllPrincipalsSet() throws AuthenticationException {
        Criteria principalsCriteria = sessionProvider.get().createCriteria(PersistedPrincipal.class);
        List<PersistedPrincipal> principals = principalsCriteria.list();
        return HibernatePrincipalUtils.getjavaSecurityPrincipals(new HashSet<PersistedPrincipal>(principals));
    }

    public void deleteUser(Subject subject) throws AuthenticationException {
        String idToString = SubjectUtils.getCredentialValueAsString(subject, false, PersistedSubject.PERSISTENCE_ID);
        if (idToString == null || idToString.equals("")) {
            throw new IllegalArgumentException("subject hasn't got any persistenceId. we cannot delete a subject not persisted ");
        }

        Session hibernateSession = sessionProvider.get();
        PersistedSubject subjectToDelete = (PersistedSubject) hibernateSession.get(PersistedSubject.class, new Long(idToString));
        hibernateSession.delete(subjectToDelete);
    }

    public boolean isEmpty() {

        Session hibernateSession = sessionProvider.get();

        Criteria orgCriteria = hibernateSession.createCriteria(Organization.class);
        List orgas = orgCriteria.list();
        if (orgas.size() > 0) {
            return false;
        }
        Criteria subjectCriteria = hibernateSession.createCriteria(PersistedSubject.class);
        List subjects = subjectCriteria.list();
        if (subjects.size() > 0) {
            return false;
        }

        Criteria principalsCriteria = hibernateSession.createCriteria(PersistedPrincipal.class);
        List principals = principalsCriteria.list();

        return principals.size() <= 0;
    }

    public void updatePrincipal(String oldPrincipalName, Principal principal) throws AuthenticationException {

        PersistedPrincipal ppal = new HibernatePrincipalUtils(sessionProvider).getPersistedPrincipal(principal);
        if (ppal != null && ppal.getId() != null) {
            sessionProvider.get().update(ppal);
        } else {
            logger.warn(" principal to update is not persisted in the database");
        }


    }

    public boolean deletePrincipal(Principal principal) throws AuthenticationException {

        PersistedPrincipal ppal = new HibernatePrincipalUtils(sessionProvider).getPersistedPrincipal(principal);
        if (ppal != null) {
            sessionProvider.get().delete(ppal);
        }

        return true;
    }


    /**
     * @return OrganizationTemplate.
     */
    @Override
    public OrganizationTemplate getOrganizationTemplate() {

        Query query = sessionProvider.get().createQuery(SELECT_ORGA_TEMPLATE);
        PersistedOrganization orga = (PersistedOrganization) query.uniqueResult();
        if (orga == null) {
            return null;
        }

        return new OrganizationTemplate(orga.toOrganization());

    }

    public void setOrganizationTemplate(OrganizationTemplate organizationTemplate) throws AuthenticationException {
        Session hibernateSession = sessionProvider.get();
        //we grab from the organization list the organizationTemplate identified by id='template'
        Query query = hibernateSession.createQuery(SELECT_ORGA_TEMPLATE);
        PersistedOrganization orga = (PersistedOrganization) query.uniqueResult();

        if (orga != null) {
            PersistedOrganization convertedOrga = new PersistedOrganization(organizationTemplate.toOrganization(), sessionProvider);
            //organizationTemplate is already present; we update it
            orga.setCredentials(convertedOrga.getCredentials());
            orga.setPrincipals(convertedOrga.getPrincipals());
            orga.setSubjectTemplate(convertedOrga.getSubjectTemplate());
            hibernateSession.update(orga);
        } else {
            PersistedOrganization newOrga = new PersistedOrganization(organizationTemplate.toOrganization(), sessionProvider);
            hibernateSession.save(newOrga);
        }

    }

    private PersistedOrganization findPersistedOrganization(String organizationName) throws HibernateException, IllegalStateException {
        Query query = sessionProvider.get().createQuery(" select organization from net.sf.jguard.ext.principals.PersistedOrganization as organization join organization.credentials as credentials where credentials.name='id' and credentials.value=:organizationId");
        query.setString("organizationId", organizationName);
        List results = query.list();
        PersistedOrganization persistedOrganization = null;
        if (results.size() > 1) {
            throw new IllegalStateException(" more than one organization is identified by " + organizationName);
        } else if (results.size() == 1) {
            persistedOrganization = (PersistedOrganization) results.get(0);
        }
        return persistedOrganization;
    }

    private PersistedOrganization getPersistedOrganizationFromSubject(Subject user) {
        Organization organization = SubjectUtils.getOrganization(user);
        return findPersistedOrganization(organization.getName());
    }


    private static Set<Subject> getJavaxSecuritySubjects(Set<PersistedSubject> jguardSubjects) {
        Set<Subject> set = new HashSet<Subject>();
        for (PersistedSubject jguardSubject : jguardSubjects) {
            Subject s = jguardSubject.toJavaxSecuritySubject();
            set.add(s);
        }
        return set;
    }
}
