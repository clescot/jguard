package net.sf.jguard.core.authorization;

import net.sf.jguard.core.authorization.permissions.MockPermission;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import java.security.Permission;


public class MockAuthorizationBindings implements AuthorizationBindings<MockRequest, MockResponse> {

    private Permission lastAccessDeniedPermission;
    private Permission postAuthenticationPermission;

    public Permission getPermissionRequested(Request request) {
        return new MockPermission("mock");
    }

    public void setLastAccessDeniedPermission(Request request, Permission lastAccessDeniedPermission) {
        this.lastAccessDeniedPermission = lastAccessDeniedPermission;
    }

    public void accessDenied(Request request, Response response) {
    }

    public void sendThrowable(Response response, Throwable t) {
    }

    public Permission getLastAccessDeniedPermission(Request<MockRequest> mockRequestRequest) {
        return lastAccessDeniedPermission;
    }

    public Permission getPostAuthenticationPermission(Request<MockRequest> mockRequestRequest) {
        return postAuthenticationPermission;
    }

    public void handlePermission(Request<MockRequest> mockRequestRequest, Response<MockResponse> mockResponseResponse, Permission permission) {

    }

    public void setPostAuthenticationPermission(Permission postAuthenticationPermission) {
        this.postAuthenticationPermission = postAuthenticationPermission;
    }


}
