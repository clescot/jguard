package net.sf.jguard.core.authorization;

import net.sf.jguard.core.authorization.permissions.MockPermission;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;
import net.sf.jguard.core.lifecycle.Request;

import java.security.Permission;


public class MockAuthorizationBindings implements AuthorizationBindings<MockRequestAdapter, MockResponseAdapter> {

    private Permission lastAccessDeniedPermission;
    private Permission postAuthenticationPermission;

    public Permission getPermissionRequested(MockRequestAdapter request) {
        return new MockPermission("mock");
    }

    public void setLastAccessDeniedPermission(Request request, Permission lastAccessDeniedPermission) {
        this.lastAccessDeniedPermission = lastAccessDeniedPermission;
    }

    public void accessDenied(MockRequestAdapter request, MockResponseAdapter response) {
    }

    public void sendThrowable(MockResponseAdapter response, Throwable t) {
    }

    public Permission getLastAccessDeniedPermission(MockRequestAdapter mockRequestRequest) {
        return lastAccessDeniedPermission;
    }

    public Permission getPostAuthenticationPermission(MockRequestAdapter mockRequestRequest) {
        return postAuthenticationPermission;
    }

    public void handlePermission(MockRequestAdapter mockRequestRequest, MockResponseAdapter mockResponseResponse, Permission permission) {

    }

    public void setPostAuthenticationPermission(Permission postAuthenticationPermission) {
        this.postAuthenticationPermission = postAuthenticationPermission;
    }


}
