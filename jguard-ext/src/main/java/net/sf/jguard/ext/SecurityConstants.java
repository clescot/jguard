/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name:  $
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
package net.sf.jguard.ext;

import javax.naming.Context;
import javax.naming.ldap.LdapContext;

/**
 * Constants related to the net.sf.jguard.core package.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles GAY</a>
 */
public interface SecurityConstants {


    //database properties
    final static String DATABASE_DRIVER = "databaseDriver";
    final static String DATABASE_DRIVER_URL = "databaseDriverUrl";
    final static String DATABASE_DRIVER_LOGIN = "databaseDriverLogin";
    final static String DATABASE_DRIVER_PASSWORD = "databaseDriverPassword";

    //JNDI constants
    final static String DIRECTORY_SEARCH_SCOPE = "directorySearchScope";
    final static String DIRECTORY_COUNT_LIMIT = "directoryCountLimit";
    final static String DIRECTORY_TIME_LIMIT = "directoryTimeLimit";
    final static String DIRECTORY_DEREF_LINK_FLAG = "directoryDerefLinkFlag";
    final static String DIRECTORY_RETURNING_ATTRIBUTES = "directoryReturningAttributes";
    final static String DIRECTORY_RETURNING_OBJ_FLAG = "directoryReturningObjFlag";
    final static String DIRECTORY_SEARCH_CONTEXT_NAME = "directorySearchContextName";
    final static String DIRECTORY_SEARCH_FILTER_EXPRESSION = "directorySearchFilterExpression";
    //JNDI "program" configuration
    //"java.naming.factory.initial"
    final String INITIAL_CONTEXT_FACTORY = Context.INITIAL_CONTEXT_FACTORY;
    //"java.naming.factory.object"
    final String OBJECT_FACTORIES = Context.OBJECT_FACTORIES;
    //"java.naming.factory.state"
    final String STATE_FACTORIES = Context.STATE_FACTORIES;
    //"java.naming.factory.url.pkgs"
    final String URL_PKG_PREFIXES = Context.URL_PKG_PREFIXES;
    //JNDI "access" configuration
    //"java.naming.provider.url"
    final String PROVIDER_URL = Context.PROVIDER_URL;
    //"java.naming.dns.url"
    final String DNS_URL = Context.DNS_URL;
    //JNDI "Service-related" configuration
    //"java.naming.authoritative"
    final String AUTHORITATIVE = Context.AUTHORITATIVE;
    //"java.naming.batchsize"
    final String BATCHSIZE = Context.BATCHSIZE;
    //"java.naming.referral"
    final String REFERRAL = Context.REFERRAL;
    //JNDI "security" configuration
    //"java.naming.security.protocol"
    final String SECURITY_PROTOCOL = Context.SECURITY_PROTOCOL;
    //"java.naming.security.authentication"
    final String SECURITY_AUTHENTICATION = Context.SECURITY_AUTHENTICATION;
    //"java.naming.security.principal"
    final String SECURITY_PRINCIPAL = Context.SECURITY_PRINCIPAL;
    //"java.naming.security.credentials"
    final String SECURITY_CREDENTIALS = Context.SECURITY_CREDENTIALS;
    //JNDI "internationalisation" configuration
    //"java.naming.language"
    final String LANGUAGE = Context.LANGUAGE;
    //JNDI "LDAP-related" program configuration
    //"java.naming.factory.control"
    final String CONTROL_FACTORIES = LdapContext.CONTROL_FACTORIES;
    final String LDAP_ATTRIBUTES_BINARY = "java.naming.ldap.attributes.binary";
    final String LDAP_CONTROL_CONNECT = "java.naming.ldap.control.connect";
    final String LDAP_DELETE_RDN = "java.naming.ldap.deleteRDN";
    final String LDAP_DEREF_ALIASES = "java.naming.ldap.derefAliases";
    final String LDAP_FACTORY_SOCKET = "java.naming.ldap.factory.socket";
    final String LDAP_REF_SEPARATOR = "java.naming.ref.separator";
    final String LDAP_REFERRAL_LIMIT = "java.naming.referral.limit";
    final String LDAP_TYPESONLY = "java.naming.ldap.typesOnly";
    final String LDAP_VERSION = "java.naming.ldap.version";
    //JNDI LDAP SASL-related parameters
    final String LDAP_SASL_AUTHORIZATION_ID = "java.naming.security.sasl.authorizationId";
    final String LDAP_SASL_CALLBACK = "java.naming.sasl.callback";
    final String LDAP_SASL_REALM = "java.naming.sasl.realm";
    final String LDAP_SASL_QOP = "javax.naming.sasl.qop";
    final String LDAP_SASL_STRENGTH = "javax.security.sasl.strength";
    final String LDAP_SASL_MAXBUFFER = "javax.security.sasl.maxbuffer";
    final String LDAP_SASL_SERVER_AUTHENTICATION = "javax.security.sasl.server.authentication";
    final String LDAP_SASL_POLICY_FORWARD = "javax.security.sasl.policy.forward";
    final String LDAP_SASL_POLICY_CREDENTIALS = "javax.security.sasl.policy.credentials";
    final String LDAP_SASL_POLICY_NOPLAINTEXT = "javax.security.sasl.policy.noplaintext";
    final String LDAP_SASL_POLICY_NOACTIVE = "javax.security.sasl.policy.noactive";
    final String LDAP_SASL_NODICTIONARY = "javax.security.sasl.policy.nodictionary";
    final String LDAP_SASL_NOANONYMOUS = "javax.security.sasl.policy.noanonymous";
    //CRL constants
    //certStore can be "LDAP" or "Collection"
    final String CERT_PATH_CERTSTORE_TYPE = "certPathCertStoreType";
    final String CERT_PATH_LDAP_SERVER_NAME = "certPathLdapServerName";
    final String CERT_PATH_LDAP_SERVER_PORT = "certPathLdapServerPort";
    final String CERT_PATH_CRL_DATE = "certPathCrlDate";
    final String CERT_PATH_CRL_TIME_ZONE = "certPathCrlTimeZone";
    final String CERT_PATH_CRL_LOCALE = "certPathCrlLocale";
    final String CERT_PATH_ISSUER_NAMES = "certPathIssuerNames";
    final String CERT_PATH_MIN_CRL_NUMBER = "certPathMinCrlNumber";
    final String CERT_PATH_MAX_CRL_NUMBER = "certPathMaxCrlNumber";
    final String CERT_PATH_CRL_PATH = "certPathCrlPath";
    final String CERT_PATH_URL_CRL_PATH = "certPathUrlCrlPath";
    final String CERT_PATH_ANY_POLICY_INHIBITED = "certPathAnyPolicyInhibited";
    final String CERT_PATH_EXPLICIT_POLICY_REQUIRED = "certPathExplicitPolicyRequired";
    final String CERT_PATH_POLICY_MAPPING_INHIBITED = "certPathPolicyMappingInhibited";
    final String CERT_PATH_POLICY_QUALIFIERS_REJECTED = "certPathPolicyQualifiersRejected";
    final String CERT_PATH_REVOCATION_ENABLED = "certPathRevocationEnabled";
    final String CERT_PATH_SIG_PROVIDER = "certPathSigProvider";
    final String CERT_STORE = "certStore";
    final String SECURITY_PROVIDER = "securityProvider";
    final String TRUSTED_CA_CERTIFICATES_DIRECTORY_PATH = "trustedCaCertsDirPath";

    final static String PASSWORD_PROMPT = "passwordField";
    //fields names used in FORM authentication
    final static String LOGIN_PROMPT = "loginField";

    final static String SECURED = "secured";
    final static String APPLICATION_PASSWORD = "applicationPassword";

    final static String DIRECTORY_PATH_TO_USER = "directoryPathToUser";


    final static String ISSUER_CA_CERT_LOCATION = "IssuerCACertLocation";
    final static String OCSP_SERVER_URL = "ocspServerURL";
    final static String OCSP_SIGNER_CERT_LOCATION = "OcspSignerCertLocation";


    //constants for JCaptcha
    static final String CAPTCHA_ANSWER = "captchaAnswer";
    static final String CAPTCHA_SERVICE = "captchaService";


    static final String NEGATIVE_PERMISSIONS = "negativePermissions";

    //certificate constants
    static final String UNIQUE_ID = "uniqueID";
    static final String DN = "DN";
    static final String PUBLIC_KEY = "publicKey";
    static final String ALTERNATIVE_NAME = "alternativeName";


    static final String JAVAX_NET_SSL_TRUSTSTORE = "javax.net.ssl.trustStore";
    static final String JAVAX_NET_SSL_TRUSTSTORE_PASSWORD = "javax.net.ssl.trustStorePassword";
    static final String KEY_STORE_PATH = "keyStorePath";
    static final String KEY_STORE_PASSWORD = "keyStorePassword";
    static final String KEY_STORE_TYPE = "keyStoreType";
    static final String AUTHORIZATION_DATABASE_CREATE_REQUIRED_DATABASE_ENTITIES = "createRequiredDatabaseEntities";
    static final String AUTHORIZATION_DATABASE_IMPORT_XML_DATA = "importXmlData";
    static final Object AUTHENTICATION_DATABASE_CREATE_REQUIRED_DATABASE_ENTITIES = "createRequiredDatabaseEntities";
}

