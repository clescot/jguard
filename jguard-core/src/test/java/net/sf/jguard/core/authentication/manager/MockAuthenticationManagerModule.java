package net.sf.jguard.core.authentication.manager;

import java.net.URL;

public class MockAuthenticationManagerModule extends AuthenticationManagerModule {
    public MockAuthenticationManagerModule(String applicationName, URL AuthenticationXmlFileLocation) {
        super(applicationName, AuthenticationXmlFileLocation, MockAuthenticationManager.class);
    }


}
