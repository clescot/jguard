package net.sf.jguard.ext.log.logback;

import ch.qos.logback.core.pattern.DynamicConverter;
import net.sf.jguard.core.authorization.permissions.RolePrincipal;

import javax.security.auth.Subject;
import java.security.AccessController;
import java.util.Set;


/**
 * grab from the current Subject, names of {@link net.sf.jguard.core.authorization.permissions.RolePrincipal}.
 */
public class RolesConverter extends DynamicConverter {
    private static final char ROLE_SEPARATOR = ',';
    public static final String NO_ROLES = "NO ROLES";

    @Override
    public String convert(Object o) {
        String roles = NO_ROLES;
        Subject subject = Subject.getSubject(AccessController.getContext());
        if (null != subject && !subject.getPrincipals(RolePrincipal.class).isEmpty()) {
            Set<RolePrincipal> roleSet = subject.getPrincipals(RolePrincipal.class);
            StringBuilder sb = new StringBuilder();
            int i = 0;
            for (RolePrincipal rp : roleSet) {
                sb.append(rp.getName());
                sb.append(ROLE_SEPARATOR);
                i++;
            }
            roles = sb.toString();
            if (i > 0) {
                roles = roles.substring(0, roles.length() - 1);
            }
        }
        return roles;
    }
}
