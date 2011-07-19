package net.sf.jguard.core.authorization.manager;


import org.dom4j.Element;

import javax.inject.Inject;
import javax.inject.Provider;

import static net.sf.jguard.core.authorization.manager.JGuardAuthorizationManagerMarkups.AUTHORIZATION_PERMISSION_RESOLUTION_CACHING;

public class PermissionResolutionCachingProvider implements Provider<Boolean> {

    private final Element authorizationElement;

    @Inject
    public PermissionResolutionCachingProvider(@AuthorizationElement Element authorizationElement){
        this.authorizationElement = authorizationElement;
    }
    public Boolean get() {
        Element permissionResolutionCachingElement = authorizationElement.element(AUTHORIZATION_PERMISSION_RESOLUTION_CACHING.getLabel());
        boolean permissionResolutionCaching = true;
               if (permissionResolutionCachingElement != null) {
                   permissionResolutionCaching = Boolean.parseBoolean(permissionResolutionCachingElement.getTextTrim());
               }

        return permissionResolutionCaching;
    }
}
