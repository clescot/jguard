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
package net.sf.jguard.ext.authentication.loginmodules;

import net.sf.jguard.core.authentication.callbacks.GuestCallbacksProvider;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.loginmodules.UserLoginModule;
import net.sf.jguard.ext.util.FastBindConnectionControl;
import net.sf.jguard.ext.util.JNDIUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.text.MessageFormat;
import java.util.*;

/**
 * JNDI - related LoginModule.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 * @see LoginModule
 */
public class JNDILoginModule extends UserLoginModule implements LoginModule {

    private static final String USER_DN = "userDN";
    private static final String CONTEXTFORCOMMIT = "contextforcommit";
    private static final String JNDI = "jndi";
    private static final String TIMELIMIT = "timelimit";
    private static final String SEARCHSCOPE = "searchscope";
    private static final String RETURNINGOBJFLAG = "returningobjflag";
    private static final String RETURNINGATTRIBUTES = "returningattributes";
    private static final String DEREFLINKFLAG = "dereflinkflag";
    private static final String COUNTLIMIT = "countlimit";
    private static final String SEARCHCONTROLS = "searchcontrols.";
    //constants
    private static final String PREAUTH = "preauth.";
    private static final String AUTH = "auth.";
    private static final String FAST_BIND_CONNECTION = "fastBindConnection";
    private static final String SEARCH_FILTER = "search.filter";
    private static final String SEARCH_BASE_DN = "search.base.dn";


    private static final Logger logger = LoggerFactory.getLogger(JNDILoginModule.class.getName());


    private DirContext preAuthContext = null;
    private DirContext authContext = null;

    //JNDI SearchControls
    private SearchControls preAuthSearchControls = null;

    private Map<String, String> authOpts = null;
    private Map preAuthOpts = null;
    private Map preAuthSearchControlsOpts = null;

    private Set credentials = null;
    private static final String LOGIN_USER_DOES_NOT_EXIST = "login.user.does.not.exist";
    private static final int FIRST_POSITION_IN_THE_COMPOSITE_NAME = 0;

    /**
     * @param subj
     * @param cbkHandler
     * @param sState
     * @param opts
     */
    @Override
    public void initialize(Subject subj, CallbackHandler cbkHandler, Map sState, Map opts) {
        super.initialize(subj, cbkHandler, sState, opts);
        preAuthOpts = new HashMap<String, String>();
        preAuthSearchControlsOpts = new HashMap();
        authOpts = new HashMap<String, String>();

        //populate specialized maps with opts
        fillOptions();

    }

    private DirContext getContext(Map opts) throws LoginException {
        DirContext context;
        if (opts.containsKey(JNDILoginModule.JNDI)) {
            Context initDirContext = null;
            try {
                initDirContext = new InitialContext();
                context = (DirContext) initDirContext.lookup((String) opts.get(JNDILoginModule.JNDI));
            } catch (NamingException e) {
                throw new LoginException(" we cannot grab the default initial context ");
            } finally {
                if (initDirContext != null) {
                    try {
                        initDirContext.close();
                    } catch (NamingException e) {
                        throw new LoginException(e.getMessage());
                    }
                }
            }

        } else {
            Control[] LDAPcontrols = getLDAPControls(opts);
            try {
                context = new InitialLdapContext(new Hashtable(opts), LDAPcontrols);
            } catch (NamingException e) {
                throw new LoginException(e.getMessage());
            }
        }
        if (context == null) {
            throw new LoginException(" we cannot grab the default initial context ");
        }
        return context;

    }

    /**
     * grab <strong>opts</strong> options and fill preAuthOpts , preAuthSearchControlsOpts and
     * authOpts options.
     */
    private void fillOptions() {
        for (Map.Entry<String, ?> stringEntry : options.entrySet()) {
            String key = (String) ((Map.Entry) stringEntry).getKey();
            String value = (String) ((Map.Entry) stringEntry).getValue();
            if (key.startsWith(JNDILoginModule.PREAUTH)) {
                key = key.substring(8, key.length());
                if (key.startsWith(JNDILoginModule.SEARCHCONTROLS)) {
                    key = key.substring(15, key.length());
                    preAuthSearchControlsOpts.put(key, value);
                } else {
                    preAuthOpts.put(key, value);
                }
            } else if (key.startsWith(JNDILoginModule.AUTH)) {
                key = key.substring(5, key.length());
                authOpts.put(key, value);
            }
        }
    }

    @Override
    protected List<Callback> getCallbacks() {
        return null;
    }

    /**
     * @return true if success, false if ignored.
     * @throws LoginException when it fails
     */
    @Override
    public boolean login() throws LoginException {
        super.login();
        if (GuestCallbacksProvider.GUEST.equals(login)) {
            //when user is a guest, we have no need to use this loginmodule
            loginOK = false;
            return false;
        }


        //userDN is null(not configured)  if preAuth is configured
        //because preAuth is used to find dynamically
        //the DN of the user
        String userDN = authOpts.get(USER_DN);
        if (preAuthOpts.size() == FIRST_POSITION_IN_THE_COMPOSITE_NAME && (userDN == null || userDN.equals(""))) {
            throw new IllegalArgumentException(" you've configured the JNDILoginmodule in 'auth' mode (options starting by 'preauth.' are not present).\n 'auth.userDN' option used to find the user LDAP Entry is lacking or is empty ");
        }


        userDN = getuserDN(userDN, login);

        if (userDN != null && !equals("")) {
            authOpts.put(Context.SECURITY_PRINCIPAL, userDN);
            authOpts.put(Context.SECURITY_CREDENTIALS, new String(password));
            try {
                authContext = getContext(authOpts);
            } finally {
                try {
                    if (authContext != null) {
                        authContext.close();
                    }
                } catch (NamingException e) {
                    throw new FailedLoginException(e.getMessage());
                }
            }
            // authentication succeed
        } else {
            loginOK = false;
            throw new LoginException(" Distinguished name is null or empty ");
        }
        //like we've already check user credentials against the directory
        //password check must not be done one more time.
        sharedState.put(SKIP_CREDENTIAL_CHECK, "true");
        logger.info(" JNDI login phase succeed for user " + login);
        return true;
    }

    /**
     * grab the Distinguished Name of the LDAP entry related to the user.
     * either a pre-authentication can be needed to execute an LDAP search, or
     * the DN can be calculated from the LDAP filter configured.
     *
     * @param userDN
     * @param login
     * @return
     * @throws LoginException
     */
    private String getuserDN(String userDN, String login) throws LoginException {
        //we prevent LDAP injection from the login
        String escapedLogin = JNDIUtils.escapeDn(login);
        Object[] args = {escapedLogin};
        if (preAuthOpts.size() > FIRST_POSITION_IN_THE_COMPOSITE_NAME) {

            //preauth initialization
            try {
                preAuthContext = getContext(preAuthOpts);
            } catch (LoginException e) {
                loginOK = false;
                throw new IllegalArgumentException(e.getMessage(), e);
            }
            preAuthSearchControlsOpts.put(COUNTLIMIT, "1");
            preAuthSearchControls = getSearchControls(preAuthSearchControlsOpts);

            try {
                userDN = preAuthSearch(preAuthContext, preAuthSearchControls);
            } catch (LoginException e) {
                loginOK = false;
                throw e;
            } finally {
                try {
                    preAuthContext.close();
                } catch (NamingException e) {
                    logger.error(e.getMessage());
                }
            }
        } else {
            userDN = MessageFormat.format(userDN, args);
            userDN = JNDIUtils.escapeDn(userDN);
        }
        return userDN;
    }


    /**
     * @return <strong>true</strong> if success, <strong>false</strong> if ignored,
     *         <strong>LoginException</strong> when it fails.
     */
    @Override
    public boolean commit() throws LoginException {
        if (!loginOK) {
            return false;
        }
        if (options.containsKey(JNDILoginModule.CONTEXTFORCOMMIT) && options.get(JNDILoginModule.CONTEXTFORCOMMIT).equals("true")) {
            credentials = grabAttributes(getContext(authOpts), authOpts.get(USER_DN));
        }

        if (credentials != null) {
            Set privateCredentials = subject.getPrivateCredentials();
            privateCredentials.addAll(credentials);
        }
        return true;
    }

    /**
     * grab the attributes of the specified LDAP entry with userDN
     * and return a credential Set.
     *
     * @param contextUsedForCommit
     * @param userDN
     * @return
     * @throws LoginException
     */
    private Set grabAttributes(DirContext contextUsedForCommit, String userDN) throws LoginException {
        DirContext userCtxt = null;
        Set creds = new HashSet();
        try {
            userCtxt = (DirContext) contextUsedForCommit.lookup(getuserDN(userDN, login));
            if (userCtxt == null) {
                throw new FailedLoginException(LOGIN_USER_DOES_NOT_EXIST);
            }

            Attributes attributes = userCtxt.getAttributes("");
            creds = grabCredentials(attributes);
        } catch (NamingException e) {
            throw new LoginException(e.getMessage());
        } finally {
            try {
                if (userCtxt != null) {
                    userCtxt.close();
                }
            } catch (NamingException e) {
                throw new LoginException(e.getMessage());
            }
        }

        return creds;
    }

    /**
     * grab attributes of the LDAP entry related to the user and
     * build a credential Set which contains attributes informations.
     *
     * @param atts
     * @return
     * @throws NamingException
     */
    private Set grabCredentials(Attributes atts) throws NamingException {
        Set credentialSet = new HashSet();
        NamingEnumeration enumeration = atts.getAll();

        while (enumeration.hasMore()) {
            Attribute attribute = (Attribute) enumeration.next();
            String key = attribute.getID();
            String value = JNDIUtils.getAttributeValue(attribute);
            JGuardCredential credential = new JGuardCredential(key, value);
            credentialSet.add(credential);
        }

        return credentialSet;
    }

    /**
     * search the Distinguished Name(DN) of the User LDAP entry.
     *
     * @param context
     * @param controls
     * @return Distinguised Name of the User found
     * @throws LoginException
     */
    private String preAuthSearch(DirContext context, SearchControls controls) throws LoginException {
        NamingEnumeration results;
        String dn = null;
        String baseDN;
        String searchFilter;
        try {
            String[] filterArgs = new String[]{super.login};
            Hashtable opts = context.getEnvironment();
            baseDN = (String) opts.get(JNDILoginModule.SEARCH_BASE_DN);
            searchFilter = (String) opts.get(JNDILoginModule.SEARCH_FILTER);

            results = context.search(baseDN, searchFilter, filterArgs, controls);
            int userFound = FIRST_POSITION_IN_THE_COMPOSITE_NAME;
            boolean grabInformations = false;
            String contextforcommit = (String) options.get(JNDILoginModule.CONTEXTFORCOMMIT);
            if (contextforcommit != null && "preauth".equals(contextforcommit)) {
                grabInformations = true;
            }
            while (results.hasMore()) {
                SearchResult result = (SearchResult) results.next();
                //the dn grabbed with getName follow the CompositeName syntax
                dn = result.getName();
                //grab the name parser of the LDAP directory
                NameParser pn = context.getNameParser("");
                //clearly declare the String as a CompositeName
                CompositeName compName = new CompositeName(result.getName());

                //grab the Name instance of the CompoundName (first position in the CompositeName)
                Name entryName = pn.parse(compName.get(FIRST_POSITION_IN_THE_COMPOSITE_NAME));
                //grab the String representation of the CompoundName
                //that's a weird way to escape special characters hadnled normally
                //by Active Directory which has got a special meaning for JNDI
                // but it works...
                dn = entryName.toString();

                if (grabInformations) {
                    credentials = grabCredentials(result.getAttributes());
                }

                userFound++;
            }
            if (userFound > 1) {
                logger.warn("more than one Distinguished Name has been found in the Directory for the user=" + login);
                throw new FailedLoginException(LOGIN_ERROR);
            }
        } catch (NamingException e) {
            throw new LoginException(" a naming exception has been raised when we are looking for the user Distinguished Name " + e.getMessage());
        } finally {
            try {
                context.close();
            } catch (NamingException e) {
                throw new LoginException(e.getMessage());
            }
        }
        if (dn == null) {
            throw new FailedLoginException(LOGIN_ERROR);
        }
        return dn;
    }

    private SearchControls getSearchControls(Map opts) {
        SearchControls controls = new SearchControls();
        for (Object o : opts.entrySet()) {
            Map.Entry entry = (Map.Entry) o;
            String key = (String) entry.getKey();
            String value = (String) entry.getValue();
            if (JNDILoginModule.COUNTLIMIT.equals(key)) {
                long countLimit = Long.parseLong(value);
                controls.setCountLimit(countLimit);
            } else if (JNDILoginModule.DEREFLINKFLAG.equals(key)) {
                boolean derefLinkFlag = Boolean.valueOf(value);
                controls.setDerefLinkFlag(derefLinkFlag);
            } else if (JNDILoginModule.RETURNINGATTRIBUTES.equals(key)) {
                String[] returningAttributes = value.split("#");
                controls.setReturningAttributes(returningAttributes);
            } else if (JNDILoginModule.RETURNINGOBJFLAG.equals(key)) {
                boolean returningobjflag = Boolean.valueOf(value);
                controls.setReturningObjFlag(returningobjflag);
            } else if (JNDILoginModule.SEARCHSCOPE.equals(key)) {
                int scope = Integer.parseInt(value);
                controls.setSearchScope(scope);
            } else if (JNDILoginModule.TIMELIMIT.equals(key)) {
                int timelimit = Integer.parseInt(value);
                controls.setTimeLimit(timelimit);
            }
        }

        return controls;
    }


    private Control[] getLDAPControls(Map opts) {
        List ldapControls = new ArrayList();
        if (opts.containsKey(JNDILoginModule.FAST_BIND_CONNECTION)
                && "true".equalsIgnoreCase((String) opts.get(JNDILoginModule.FAST_BIND_CONNECTION))) {
            ldapControls.add(new FastBindConnectionControl());
        }
        return (Control[]) ldapControls.toArray(new Control[ldapControls.size()]);

    }

}
