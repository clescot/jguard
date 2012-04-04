package net.sf.jguard.core.authorization.permissions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Permission;

/**
 * wrap a Permission instance to audit its checks.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
class AuditPermission extends Permission {

    private Permission permission;
    private static Logger logger = LoggerFactory.getLogger(AuditPermission.class.getName());

    public AuditPermission(Permission permission) {
        super(permission.getName());
        this.permission = permission;
    }

    /**
     * Checks if the specified permission's actions are "implied by"
     * this object's actions.
     * <p/>
     * This must be implemented by subclasses of Permission, as they are the
     * only ones that can impose semantics on a Permission object.
     * <p/>
     * <p>The <code>implies</code> method is used by the AccessController to determine
     * whether or not a requested permission is implied by another permission that
     * is known to be valid in the current execution context.
     *
     * @param permissionToCheck the permission to check against.
     * @return true if the specified permission is implied by this object,
     *         false if not.
     */
    public boolean implies(Permission permissionToCheck) {
        if (!(permissionToCheck instanceof AuditPermission)) {
            return false;
        }
        AuditPermission permToCheck = (AuditPermission) permissionToCheck;
        boolean result = this.permission.implies(permToCheck.permission);
        logger.debug(" permission" + this.permission.toString() + "check " + permissionToCheck.toString() + " result=" + result);
        return result;
    }

    /**
     * Checks two Permission objects for equality.
     * <p/>
     * Do not use the <code>equals</code> method for making access control
     * decisions; use the <code>implies</code> method.
     *
     * @param obj the object we are testing for equality with this object.
     * @return true if both Permission objects are equivalent.
     */
    public boolean equals(Object obj) {
        if (!(obj instanceof AuditPermission)) {
            return false;
        }
        return this.permission.equals(((AuditPermission) obj).permission);
    }

    /**
     * Returns the hash code value for this Permission object.
     * <p/>
     * The required <code>hashCode</code> behavior for Permission Objects is
     * the following: <p>
     * <ul>
     * <li>Whenever it is invoked on the same Permission object more than
     * once during an execution of a Java application, the
     * <code>hashCode</code> method
     * must consistently return the same integer. This integer need not
     * remain consistent from one execution of an application to another
     * execution of the same application. <p>
     * <li>If two Permission objects are equal according to the
     * <code>equals</code>
     * method, then calling the <code>hashCode</code> method on each of the
     * two Permission objects must produce the same integer result.
     * </ul>
     *
     * @return a hash code value for this object.
     */
    public int hashCode() {
        return permission.hashCode();
    }

    /**
     * Returns the actions as a String. This is abstract
     * so subclasses can defer creating a String representation until
     * one is needed. Subclasses should always return actions in what they
     * consider to be their
     * canonical form. For example, two FilePermission objects created via
     * the following:
     * <p/>
     * <pre>
     *   perm1 = new FilePermission(p1,"read,write");
     *   perm2 = new FilePermission(p2,"write,read");
     * </pre>
     * <p/>
     * both return
     * "read,write" when the <code>getActions</code> method is invoked.
     *
     * @return the actions of this Permission.
     */
    public String getActions() {
        return permission.getActions();
    }
}
