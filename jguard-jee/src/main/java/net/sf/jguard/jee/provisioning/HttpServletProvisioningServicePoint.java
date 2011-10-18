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

package net.sf.jguard.jee.provisioning;

import net.sf.jguard.core.authentication.StatefulAuthenticationServicePoint;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.manager.AuthenticationManager;
import net.sf.jguard.core.authorization.filters.LastAccessDeniedFilter;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import net.sf.jguard.core.principals.SubjectTemplate;
import net.sf.jguard.core.provisioning.ProvisioningServicePoint;
import net.sf.jguard.core.util.CryptUtils;
import net.sf.jguard.core.util.XMLUtils;
import net.sf.jguard.jee.HttpConstants;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.lifecycle.AnonymizerRequestWrapper;
import org.dom4j.Document;
import org.dom4j.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.Permissions;
import java.util.*;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class HttpServletProvisioningServicePoint implements ProvisioningServicePoint<HttpServletRequest, HttpServletResponse> {

    private static final Logger logger = LoggerFactory.getLogger(HttpServletProvisioningServicePoint.class.getName());
    private String registerURI;
    private URLPermission registerProcessPermission;
    private URLPermission registerPermission;
    private static final String J_GUARD_FILTER_2_0_0_XSD = "jGuardFilter_2.0.0.xsd";
    private AuthenticationManager authenticationManager;

    /**
     * Creates a new instance of HttpServletProvisioningServicePoint
     */
    @Inject
    public HttpServletProvisioningServicePoint(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    public void init(URL location) {
        setSettings(loadFilterConfiguration(location));

    }

    public Permission getRegisterPermission() {
        return registerPermission;
    }

    public Permission getRegisterProcessPermission() {
        return registerProcessPermission;
    }

    public boolean registerProcess(Request<HttpServletRequest> req, Response<HttpServletResponse> res) {
        boolean registerSucceed = registerCoreProcess(req);
        HttpServletRequest request = req.get();
        HttpServletResponse response = res.get();
        boolean result = false;
        if (!registerSucceed) {
            logger.debug(" registration failed ", " registerProcess phase ");

            if (!response.isCommitted()) {
                try {
                    if(URLPermission.REDIRECT.equalsIgnoreCase(registerPermission.getDispatch())){
                    response.sendRedirect(response.encodeRedirectURL(request.getContextPath() + registerURI));
                    }else{
                        request.getRequestDispatcher(registerURI).forward(request,response);
                    }
                } catch (IOException e) {
                    logger.warn(" we cannot dispatch to " + request.getContextPath() + registerURI + " because " + e.getMessage());
                } catch (ServletException e) {
                    logger.warn(" we cannot dispatch to " + request.getContextPath() + registerURI + " because " + e.getMessage());
                }
            } else {
                logger.warn(" we cannot dispatch to " + request.getContextPath() + registerURI + " because response is already commited ");
            }
            result = false;
        } else {
            logger.debug(" registration succeed ", " registerProcess phase ");
            //the user is registered and we submit directly its credentials to the authentication phase
            request.getSession(true).removeAttribute(StatefulAuthenticationServicePoint.LOGIN_CONTEXT_WRAPPER);
            request.getSession(true).removeAttribute(LastAccessDeniedFilter.LAST_ACCESS_DENIED_PERMISSION);
            result = true;

        }
        return result;
    }

    /**
     * register the user against the @link SubjectTemplate.
     *
     * @param req
     * @return true if registration succeed, false otherwise
     */
    public boolean registerCoreProcess(Request<HttpServletRequest> req) {
        HttpServletRequest request = req.get();
        boolean success;
        SubjectTemplate st = null;
        try {
            st = buildSubjectTemplate(request);
        } catch (AuthenticationException e1) {
            logger.error(" subject template cannot be built ", e1);
            return false;
        }
        String passwordField = "password";
        Set<JGuardCredential> credentials = st.getRequiredCredentials();
        JGuardCredential passwordCredential = null;
        for (JGuardCredential cred : credentials) {
            if (cred.getName().equals(passwordField)) {
                passwordCredential = cred;
                break;
            }

        }

        if (passwordCredential == null) {
            logger.warn("JGuardTagCredential matching  passwordField not found in the SubjectTemplate");
            success = false;
            return success;
        }
        char[] password = (passwordCredential.getValue().toString()).toCharArray();

        try {
            credentials.remove(passwordCredential);
            credentials.add(new JGuardCredential(passwordCredential.getName(), CryptUtils.cryptPassword(password).toString()));
        } catch (NoSuchAlgorithmException ex) {
            logger.warn(ex.getMessage());
            success = false;
            return success;
        }

        try {
            authenticationManager.createUser(st, authenticationManager.getDefaultOrganization());
            success = true;
        } catch (AuthenticationException e) {
            logger.debug(" registrationProcess failed ");
            success = false;
        }

        return success;
    }


    public Request<HttpServletRequest> anonymize(Request<HttpServletRequest> req) {
        HttpServletRequest request = req.get();
        return new HttpServletRequestAdapter(new AnonymizerRequestWrapper(request));
    }

    /**
     * fill in the SubjectTemplate the credentials from HttpServletRequest.
     *
     * @param req HttpServletRequest
     * @return SubjectTemplate filled.
     * @throws AuthenticationException
     */
    private SubjectTemplate buildSubjectTemplate(HttpServletRequest req) throws AuthenticationException {
        SubjectTemplate defaultSt = authenticationManager.getDefaultOrganization().getSubjectTemplate();
        SubjectTemplate st = new SubjectTemplate();


        //private required credentials
        Set privateCredRequiredFromDefaultSt = defaultSt.getPrivateRequiredCredentials();
        Set<JGuardCredential> privRequiredCred = grabRegistrationForm(req, privateCredRequiredFromDefaultSt);
        st.setPrivateRequiredCredentials(privRequiredCred);

        //public required credentials
        Set publicCredRequiredFromDefaultSt = defaultSt.getPublicRequiredCredentials();
        Set<JGuardCredential> pubRequiredCred = grabRegistrationForm(req, publicCredRequiredFromDefaultSt);
        st.setPublicRequiredCredentials(pubRequiredCred);

        //public optional credentials
        Set publicCredOptionalFromDefaultSt = defaultSt.getPublicOptionalCredentials();
        Set<JGuardCredential> pubOptionalCred = grabRegistrationForm(req, publicCredOptionalFromDefaultSt);
        st.setPublicOptionalCredentials(pubOptionalCred);

        //public optional credentials
        Set privateCredOptionalFromDefaultSt = defaultSt.getPrivateOptionalCredentials();
        Set<JGuardCredential> privOptionalCred = grabRegistrationForm(req, privateCredOptionalFromDefaultSt);
        st.setPrivateOptionalCredentials(privOptionalCred);


        return st;
    }

    /**
     * build a set of credentials by grabbing data from HttpServletRequest.
     *
     * @param req                      HttpServletRequest
     * @param credentialsFromDefaultSt
     * @return Set of {@link JGuardCredential}
     */
    private static Set<JGuardCredential> grabRegistrationForm(HttpServletRequest req, Set credentialsFromDefaultSt) {
        Iterator itCredentials = credentialsFromDefaultSt.iterator();
        Set<JGuardCredential> credSet = new HashSet<JGuardCredential>();
        while (itCredentials.hasNext()) {
            JGuardCredential jcredFromDefault = (JGuardCredential) itCredentials.next();

            //test if we've found the credential in the http request
            if (req.getParameter(jcredFromDefault.getName()) != null) {

                try {
                    JGuardCredential jcred = new JGuardCredential(jcredFromDefault.getName(), req.getParameter(jcredFromDefault.getName()));
                    credSet.add(jcred);
                } catch (IllegalArgumentException iae) {
                    logger.warn(" the property " + jcredFromDefault.getName() + " doesn't exist in the HttpServletRequest ");
                }
            }

        }
        return credSet;
    }

    /**
     * load configuration from an XML file.
     *
     * @param configurationLocation
     * @return Map containing filter configuration
     */
    private Map<String, String> loadFilterConfiguration(URL configurationLocation) {
        URL url = Thread.currentThread().getContextClassLoader().getResource(J_GUARD_FILTER_2_0_0_XSD);
        Document doc = XMLUtils.read(configurationLocation,url );

        Element authentication = doc.getRootElement();
        Map<String, String> filterSettings = new HashMap<String, String>();
        if (authentication.element(HttpConstants.REGISTER_PROCESS_URI) != null) {
            filterSettings.put(HttpConstants.REGISTER_PROCESS_URI, authentication.element(HttpConstants.REGISTER_PROCESS_URI).getTextTrim());
        }
        if (authentication.element(HttpConstants.REGISTER_URI) != null) {
            filterSettings.put(HttpConstants.REGISTER_URI, authentication.element(HttpConstants.REGISTER_URI).getTextTrim());
        }

        filterSettings.put(HttpConstants.AUTH_SCHEME, authentication.element(HttpConstants.AUTH_SCHEME).getTextTrim());
        Element loginElement = authentication.element(HttpConstants.LOGIN_FIELD);
        if (loginElement != null) {
            filterSettings.put(HttpConstants.LOGIN_FIELD, loginElement.getTextTrim());
        }
        Element passwordElement = authentication.element(HttpConstants.PASSWORD_FIELD);
        if (passwordElement != null) {
            filterSettings.put(HttpConstants.PASSWORD_FIELD, passwordElement.getTextTrim());
        }


        return filterSettings;
    }


    /**
     * @param settings Map which contains filter options
     */
    private void setSettings(Map<String, String> settings) {

        registerProcessPermission = new URLPermission(HttpConstants.REGISTER_PROCESS_URI, settings.get(HttpConstants.REGISTER_PROCESS_URI));
        registerURI = settings.get(HttpConstants.REGISTER_URI);
        registerPermission = new URLPermission(HttpConstants.REGISTER_URI, registerURI);

    }


    public Permissions getGrantedPermissions() {

        Permissions alwaysGrantedPermissions = new Permissions();
        alwaysGrantedPermissions.add(getRegisterPermission());
        alwaysGrantedPermissions.add(getRegisterProcessPermission());
        return alwaysGrantedPermissions;
    }

}
