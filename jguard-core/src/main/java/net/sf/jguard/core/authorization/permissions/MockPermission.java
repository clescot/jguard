package net.sf.jguard.core.authorization.permissions;

import java.security.BasicPermission;

public class MockPermission extends BasicPermission {
    public MockPermission(String name) {
        super(name);
    }

    public MockPermission(String name, String actions) {
        super(name, actions);
    }
}
