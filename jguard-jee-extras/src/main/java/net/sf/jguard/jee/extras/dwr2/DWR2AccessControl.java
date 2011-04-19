/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package net.sf.jguard.jee.extras.dwr2;

import com.google.inject.Inject;
import net.sf.jguard.jee.authorization.HttpAccessControllerUtils;
import org.directwebremoting.extend.Creator;
import org.directwebremoting.impl.DefaultAccessControl;
import uk.ltd.getahead.dwr.WebContextFactory;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;
import java.security.AccessControlException;
import java.security.Permission;
import java.security.PrivilegedActionException;

/**
 * link DWR with jguard to unify access control in jguard.
 * this implementation works in DWR 2.x.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class DWR2AccessControl extends DefaultAccessControl {
    private HttpAccessControllerUtils httpAccessControllerUtils;

    @Inject
    public DWR2AccessControl(HttpAccessControllerUtils httpAccessControllerUtils) {
        super();
        this.httpAccessControllerUtils = httpAccessControllerUtils;
    }


    public void assertExecutionIsPossible(Creator creator, String className, Method method) {
        //TODO implements DWR1Authorizationbindings, DWR1AuthenticationBindings and
        //DWR2Authorizationbindings, DWR2AuthenticationBindings
        //http://fisheye5.cenqua.com/browse/dwr/java/org/directwebremoting/impl/DefaultAccessControl.java?r=1.15
        StringBuffer actions = new StringBuffer();
        actions.append(creator.getClass().getName());
        actions.append(",");
        actions.append(creator.getType().getName());
        actions.append(",");
        actions.append(method.getName());
        Permission p = new DWR2Permission("dummy name created by DWR2AccessControl to check access  ", actions.toString());
        HttpServletRequest req = WebContextFactory.get().getHttpServletRequest();
        try {
            httpAccessControllerUtils.checkPermission(req.getSession(true), p);
        } catch (AccessControlException ex) {
            throw new SecurityException(ex);
        } catch (PrivilegedActionException ex) {
            throw new SecurityException(ex);
        }
    }


    public void addRoleRestriction(String scriptName, String methodName, String role) {
        super.addRoleRestriction(scriptName, methodName, role);
    }

    public void addIncludeRule(String scriptName, String methodName) {
        super.addIncludeRule(scriptName, methodName);
    }

    public void addExcludeRule(String scriptName, String methodName) {
        super.addExcludeRule(scriptName, methodName);
    }

}
