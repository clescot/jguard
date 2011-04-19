package net.sf.jguard.jsf;

import com.google.inject.Inject;
import net.sf.jguard.core.authentication.Stateful;
import net.sf.jguard.core.authentication.filters.AuthenticationFilter;
import net.sf.jguard.core.authorization.filters.AuthorizationFilter;
import net.sf.jguard.core.enforcement.PolicyEnforcementPoint;
import net.sf.jguard.core.lifecycle.Response;

import javax.faces.application.Application;
import javax.faces.application.FacesMessage;
import javax.faces.application.NavigationHandler;
import javax.faces.context.FacesContext;
import java.text.MessageFormat;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;

public class JSFPolicyEnforcementPoint extends PolicyEnforcementPoint<FacesContext, FacesContext> {
    @Inject
    public JSFPolicyEnforcementPoint(@Stateful List<AuthenticationFilter<FacesContext, FacesContext>> authenticationFilters,
                                     List<AuthorizationFilter<FacesContext, FacesContext>> authorizationFilters,
                                     boolean propagateThrowable) {
        super(authenticationFilters, authorizationFilters, propagateThrowable);
    }


    /**
     * add a FacesMessage with a "throwable" key, and an ERROR severity to the FacesContext.
     * it forwards also to a "throwable" outcome.
     *
     * @param response
     * @param t
     */
    @Override
    public void sendThrowable(Response response, Throwable t) {
        String outcomeThrowable = "throwable";
        FacesContext facesContext = FacesContext.getCurrentInstance();
        NavigationHandler nh = facesContext.getApplication().getNavigationHandler();
        nh.handleNavigation(facesContext, null, outcomeThrowable);
        String[] params = {t.getLocalizedMessage()};
        String msg = getLocalizedAndFormattedMessage(facesContext, outcomeThrowable, params);
        if ("".equals(msg)) {
            msg = t.getLocalizedMessage();
        }
        FacesMessage facesMsg = new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, msg);
        facesContext.addMessage(null, facesMsg);

    }

    /**
     * return an localized message according to the Locale from the view root,
     * localized with a message key and parameters
     *
     * @param context    global JSF context
     * @param messageKey key to localize
     * @param params     can be null
     * @return localized string
     */
    private String getLocalizedAndFormattedMessage(FacesContext context, String messageKey, Object[] params) {
        // this method is inspired from this book excerpt:
        //http://www.onjava.com/pub/a/onjava/excerpt/JSF_chap8/index.html?page=3
        Application application = context.getApplication();
        String messageBundleName = application.getMessageBundle();
        Locale locale = context.getViewRoot().getLocale();
        if (messageBundleName == null || "".equals(messageBundleName)) {
            return "";
        }
        ResourceBundle rb = ResourceBundle.getBundle(messageBundleName, locale);
        String msgPattern = rb.getString(messageKey);
        String msg = msgPattern;
        if (params != null) {
            msg = MessageFormat.format(msgPattern, params);
        }
        return msg;
    }
}
