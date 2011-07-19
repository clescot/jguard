package net.sf.jguard.core.authorization.manager;


import org.dom4j.Element;

import javax.inject.Inject;
import javax.inject.Provider;

import static net.sf.jguard.core.authorization.manager.JGuardAuthorizationManagerMarkups.NEGATIVE_PERMISSIONS;

public class NegativePermissionsProvider implements Provider<Boolean> {

    private final Element authorizationElement;
    @Inject
    public NegativePermissionsProvider(@AuthorizationElement Element authorizationElement){
        this.authorizationElement = authorizationElement;
    }
    public Boolean get() {
         Element negativePermissionsElement = authorizationElement.element(NEGATIVE_PERMISSIONS.getLabel());
        boolean negativePermission = false;
               if (negativePermissionsElement != null) {
                   negativePermission = Boolean.parseBoolean(negativePermissionsElement.getTextTrim());
               }

        return negativePermission;
    }
}
