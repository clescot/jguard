package net.sf.jguard.core.authentication;

import net.sf.jguard.core.authentication.callbackhandler.AsynchronousMockCallbackHandler;
import net.sf.jguard.core.authentication.callbackhandler.MockCallbackHandler;
import net.sf.jguard.core.authentication.loginmodules.MockLoginModule;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

public class AbstractAuthenticationServicePointTest {

    private final String applicationName = "jguard-struts-example";

    @Mock
    private Configuration configuration;

    @Mock
    private AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> authenticationSchemeHandler;

    private AbstractAuthenticationServicePoint abstractAuthenticationServicePoint;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);


    }

    @Test
    public void testAuthenticate_when_no_AppConfiguration_into_Configuration_is_linked_to_the_application_name() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        abstractAuthenticationServicePoint.authenticate(new MockCallbackHandler(req, res, authenticationSchemeHandlers));

    }

    @Test
    public void testAuthenticate_succeed() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        AppConfigurationEntry[] entries = getAppConfigurationEntriesWithOneMockLoginModule();
        when(configuration.getAppConfigurationEntry(applicationName)).thenReturn(entries);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        AuthenticationResult authenticationResult = abstractAuthenticationServicePoint.authenticate(new AsynchronousMockCallbackHandler(req, res, authenticationSchemeHandlers));
        assertThat(authenticationResult.getStatus(), is(AuthenticationStatus.SUCCESS));
    }


    @Test
    public void testAuthenticate_fails() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        AppConfigurationEntry[] entries = getAppConfigurationEntriesWithOneMockLoginModule();
        when(configuration.getAppConfigurationEntry(applicationName)).thenReturn(entries);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        AuthenticationResult authenticationResult = abstractAuthenticationServicePoint.authenticate(new AsynchronousMockCallbackHandler(req, res, authenticationSchemeHandlers));
        assertThat(authenticationResult.getStatus(), is(AuthenticationStatus.SUCCESS));
    }


    @Test
    public void testAuthenticate_asynchronously_Yes_answerToChallenge_Yes_challengeNeeded_No_status_SUCCESS() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        AppConfigurationEntry[] entries = getAppConfigurationEntriesWithOneMockLoginModule();
        when(configuration.getAppConfigurationEntry(applicationName)).thenReturn(entries);
        when(authenticationSchemeHandler.answerToChallenge(req, res)).thenReturn(true);
        when(authenticationSchemeHandler.impliesChallenge()).thenReturn(false);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        AuthenticationResult authenticateResult = abstractAuthenticationServicePoint.authenticate(new AsynchronousMockCallbackHandler(req, res, authenticationSchemeHandlers));
        assertThat(authenticateResult.getStatus(), is(AuthenticationStatus.SUCCESS));
    }

    @Test
    public void testAuthenticate_asynchronously_Yes_answerToChallenge_No_challengeNeeded_No_status_SUCCESS() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        AppConfigurationEntry[] entries = getAppConfigurationEntriesWithOneMockLoginModule();
        when(configuration.getAppConfigurationEntry(applicationName)).thenReturn(entries);
        when(authenticationSchemeHandler.answerToChallenge(req, res)).thenReturn(false);
        when(authenticationSchemeHandler.impliesChallenge()).thenReturn(false);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        AuthenticationResult authenticateResult = abstractAuthenticationServicePoint.authenticate(new AsynchronousMockCallbackHandler(req, res, authenticationSchemeHandlers));
        assertThat(authenticateResult.getStatus(), is(AuthenticationStatus.SUCCESS));
    }


    @Test
    public void testAuthenticate_asynchronously_Yes_answerToChallenge_No_challengeNeeded_Yes_status_FAILURE() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        AppConfigurationEntry[] entries = getAppConfigurationEntriesWithOneMockLoginModule();
        when(configuration.getAppConfigurationEntry(applicationName)).thenReturn(entries);
        when(authenticationSchemeHandler.answerToChallenge(req, res)).thenReturn(false);
        when(authenticationSchemeHandler.impliesChallenge()).thenReturn(true);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        AuthenticationResult authenticateResult = abstractAuthenticationServicePoint.authenticate(new AsynchronousMockCallbackHandler(req, res, authenticationSchemeHandlers));
        assertThat(authenticateResult.getStatus(), is(AuthenticationStatus.FAILURE));
    }


    @Test
    public void testAuthenticate_asynchronously_No_answerToChallenge_Yes_challengeNeeded_Yes_status_FAILURE() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        AppConfigurationEntry[] entries = getAppConfigurationEntriesWithOneMockLoginModule();
        when(configuration.getAppConfigurationEntry(applicationName)).thenReturn(entries);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        AuthenticationResult authenticateResult = abstractAuthenticationServicePoint.authenticate(new MockCallbackHandler(req, res, authenticationSchemeHandlers));
        assertThat(authenticateResult.getStatus(), is(AuthenticationStatus.SUCCESS));
    }

    @Test
    public void testAuthenticate_asynchronously_No_answerToChallenge_Yes_challengeNeeded_No_status_SUCCESS() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        AppConfigurationEntry[] entries = getAppConfigurationEntriesWithOneMockLoginModule();
        when(configuration.getAppConfigurationEntry(applicationName)).thenReturn(entries);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        AuthenticationResult authenticateResult = abstractAuthenticationServicePoint.authenticate(new MockCallbackHandler(req, res, authenticationSchemeHandlers));
        assertThat(authenticateResult.getStatus(), is(AuthenticationStatus.SUCCESS));
    }

    @Test
    public void testAuthenticate_asynchronously_No_answerToChallenge_No_challengeNeeded_No_status_SUCCESS() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        AppConfigurationEntry[] entries = getAppConfigurationEntriesWithOneMockLoginModule();
        when(configuration.getAppConfigurationEntry(applicationName)).thenReturn(entries);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        AuthenticationResult authenticateResult = abstractAuthenticationServicePoint.authenticate(new MockCallbackHandler(req, res, authenticationSchemeHandlers));
        assertThat(authenticateResult.getStatus(), is(AuthenticationStatus.SUCCESS));
    }


    @Test
    public void testAuthenticate_asynchronously_No_answerToChallenge_No_challengeNeeded_Yes_status_FAILURE() throws Exception {
        //given
        MockRequestAdapter req = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter res = new MockResponseAdapter(new MockResponse());
        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);
        AppConfigurationEntry[] entries = getAppConfigurationEntriesWithOneMockLoginModule();
        when(configuration.getAppConfigurationEntry(applicationName)).thenReturn(entries);
        LoginContextWrapper loginContextWrapper = new LoginContextWrapperImpl(applicationName, configuration);
        abstractAuthenticationServicePoint = new AbstractAuthenticationServicePoint(loginContextWrapper) {
        };
        //when
        AuthenticationResult authenticateResult = abstractAuthenticationServicePoint.authenticate(new MockCallbackHandler(req, res, authenticationSchemeHandlers));
        assertThat(authenticateResult.getStatus(), is(AuthenticationStatus.SUCCESS));
    }


    private AppConfigurationEntry[] getAppConfigurationEntriesWithOneMockLoginModule() {
        AppConfigurationEntry entry = new AppConfigurationEntry(MockLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap());
        return new AppConfigurationEntry[]{entry};
    }


    @Test
    public void testImpersonateAsGuest() throws Exception {

    }

    @Test
    public void testAnswerToChallenge() throws Exception {

    }

    @Test
    public void testGetCurrentSubject() throws Exception {

    }

    @Test
    public void testGetGuestSubject() throws Exception {

    }

    @Test
    public void testAuthenticationSucceededDuringThisRequest() throws Exception {

    }
}
