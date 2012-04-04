package net.sf.jguard.jee.taglib;

import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.jee.HttpConstants;
import org.apache.taglibs.standard.lang.support.ExpressionEvaluatorManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;
import java.io.IOException;
import java.util.Iterator;
import java.util.Set;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public abstract class JGuardTagCredential extends TagSupport implements HttpConstants {
    protected String id = "";
    protected String def;

    private static final Logger logger = LoggerFactory.getLogger(JGuardTagCredential.class);

    private String visibility;

    public JGuardTagCredential() {
        if (isPrivate()) {
            visibility = "private";
        } else {
            visibility = "public";
        }
    }

    protected abstract Set<JGuardCredential> getCredentials(Subject subject);

    protected abstract boolean isPrivate();

    protected abstract String getTagName();

    public int doEndTag() throws JspException {
        String value = null;
        String defaut = (String) ExpressionEvaluatorManager.evaluate("default", def, String.class, this, pageContext);

        String name = (String) ExpressionEvaluatorManager.evaluate("id", id, String.class, this, pageContext);
        Subject subject = TagUtils.getSubject(pageContext);
        try {
            if (subject != null) {

                Set credentials = getCredentials(subject);
                Iterator it = credentials.iterator();
                JGuardCredential cred = null;

                while (it.hasNext()) {
                    cred = (JGuardCredential) it.next();
                    // if the id wanted by the webapp developer
                    // is encountered in the public credentials subject
                    if (cred.getName().equals(name)) {
                        value = cred.getValue().toString();
                        break;
                    }
                }
            }
        } catch (SecurityException sex) {
            if (logger.isErrorEnabled()) {
                logger.error("doEndTag() - you don't have the permission to access to the " + visibility + " credentialsn");
            }
            if (logger.isErrorEnabled()) {
                logger.error("doEndTag() - you should contact your administrator server n ");
            }
            value = "you don't have the permission to access to the " + visibility + " credentials";
        }
        if (value == null && defaut != null) {
            value = defaut;
        } else if (name == null) {
            value = "";
        }

        if (logger.isDebugEnabled()) {
            logger.debug("<jguard:" + getTagName() + "> id=" + this.id);
            logger.debug("<jguard:" + getTagName() + "> default=" + defaut);
            logger.debug("<jguard:" + getTagName() + "> value=" + value);
        }
        try {
            // output the value
            pageContext.getOut().print(value);
        } catch (IOException e) {
            logger.error("doEndTag()", e);
        }

        return EVAL_PAGE;
    }


    /**
     * @return id
     */
    public String getId() {
        return id;
    }

    /**
     * @param id
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * @return Returns the def.
     */
    public String getDefault() {
        return def;
    }

    /**
     * @param def The def to set.
     */
    public void setDefault(String def) {
        this.def = def;
    }
}
