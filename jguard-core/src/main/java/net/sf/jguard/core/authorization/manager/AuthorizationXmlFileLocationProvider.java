package net.sf.jguard.core.authorization.manager;

import net.sf.jguard.core.AuthorizationManagerOptions;

import javax.inject.Inject;
import javax.inject.Provider;
import java.util.Map;

public class AuthorizationXmlFileLocationProvider implements Provider<String>{

    private final Map<String, String> authorizationManagerOptions;

    @Inject
    public AuthorizationXmlFileLocationProvider(@AuthorizationManagerOptions Map<String,String> authorizationManagerOptions){
        this.authorizationManagerOptions = authorizationManagerOptions;
    }

    public String get() {
        String authorizationXmlFileLocation = authorizationManagerOptions.get(JGuardAuthorizationManagerMarkups.AUTHORIZATION_XML_FILE_LOCATION.getLabel());
        if(authorizationXmlFileLocation==null){
            throw new IllegalArgumentException(JGuardAuthorizationManagerMarkups.AUTHORIZATION_XML_FILE_LOCATION.getLabel()+" option is not present");
        }
        return authorizationXmlFileLocation;
    }
}
