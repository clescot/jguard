package net.sf.jguard.jee.authentication.schemes;

import net.sf.jguard.core.authorization.permissions.PermissionFactory;
import net.sf.jguard.core.authorization.permissions.URLPermission;
import net.sf.jguard.core.technology.StatefulScopes;
import net.sf.jguard.ext.authentication.schemes.JCaptchaAuthenticationSchemeHandler;
import net.sf.jguard.jee.HttpConstants;
import net.sf.jguard.jee.HttpPermissionFactory;
import net.sf.jguard.jee.HttpServletRequestAdapter;
import net.sf.jguard.jee.HttpServletResponseAdapter;

import javax.servlet.http.HttpServletRequest;
import java.security.Permission;
import java.util.Map;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class HttpServletJcaptchaAuthenticationSchemeHandler extends JCaptchaAuthenticationSchemeHandler<HttpServletRequestAdapter, HttpServletResponseAdapter> {

    private static final String LOGON_PROCESS_URI = "logonProcessURI";
    private static final String CAPTCHA_ANSWER_PARAMETER = "captchaAnswerParameter";
    private String captchaAnswerParameter;

    public HttpServletJcaptchaAuthenticationSchemeHandler(Map<String, String> parameters,
                                                          StatefulScopes authenticationBindings) {
        super(parameters, authenticationBindings);
        String logonProcessURI = parameters.get(LOGON_PROCESS_URI);
        logonProcessPermission = new URLPermission(LOGON_PROCESS_URI, logonProcessURI);
        String logonURI = parameters.get(HttpConstants.LOGON_URI);
        logonPermission = new URLPermission(HttpConstants.LOGON_URI, logonURI);
        String logoffURI = parameters.get(HttpConstants.LOGOFF_URI);
        logoffPermission = new URLPermission(HttpConstants.LOGOFF_URI, logoffURI);
        captchaAnswerParameter = parameters.get(CAPTCHA_ANSWER_PARAMETER);
        buildGrantedPermissions();
    }

    /**
     * @return Permission bound to the FORM target.
     */
    protected Permission getLogonProcessPermission() {
        return logonProcessPermission;
    }

    public Permission getLogoffPermission() {
        return logoffPermission;
    }

    public Permission getLogonPermission() {
        return logonPermission;
    }

    /**
     * return the PermissionFactory.
     *
     * @return
     */
    protected PermissionFactory<HttpServletRequestAdapter> getPermissionFactory() {
        return new HttpPermissionFactory();
    }

    /**
     * create a challenge in the underlying technology way.
     *
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    public void buildChallenge(HttpServletRequestAdapter request, HttpServletResponseAdapter response) {
        //with HttpServlet, captcha generation is handled externally
    }

    protected String getCaptchaAnswer(HttpServletRequestAdapter request, HttpServletResponseAdapter response) {
        HttpServletRequest req = request.get();
        return req.getParameter(captchaAnswerParameter);
    }

    protected String getSessionID(HttpServletRequestAdapter request) {
        HttpServletRequest req = request.get();
        return req.getSession(true).getId();
    }
}
