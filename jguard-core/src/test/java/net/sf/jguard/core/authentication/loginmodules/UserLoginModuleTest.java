package net.sf.jguard.core.authentication.loginmodules;

import com.google.common.collect.Lists;
import net.sf.jguard.core.authentication.callbackhandler.MockCallbackHandler;
import net.sf.jguard.core.authentication.credentials.JGuardCredential;
import net.sf.jguard.core.authentication.manager.JGuardAuthenticationManagerMarkups;
import net.sf.jguard.core.authentication.manager.MockAuthenticationManager;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.authentication.schemes.HookImplFormSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import java.util.*;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;

public class UserLoginModuleTest {

    public static final String NAME_FRM_HOOK_FORM_SCHEME_HANDLER = "HOOK";
    private UserLoginModule userLoginModule;
    private ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers;
    private MockCallbackHandler callbackHandler;
    private MockAuthenticationManager mockAuthenticationManager;

    @Mock
    private CallbackHandler mockCallbackHandler;
    @InjectMocks
    private UserLoginModule mockUserLoginModule = new UserLoginModule() {
        @Override
        protected List<Callback> getCallbacks() {
            List<Callback> list = Lists.newArrayList();
            list.add(new NameCallback("dummy"));
            return list;
        }
    };

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        userLoginModule = new UserLoginModule() {
            @Override
            protected List<Callback> getCallbacks() {
                List<Callback> list = Lists.newArrayList();
                list.add(new NameCallback("dummy"));
                return list;
            }
        };
        authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(new HookImplFormSchemeHandler(null));
        callbackHandler = new MockCallbackHandler(null, null, authenticationSchemeHandlers);
        mockAuthenticationManager = new MockAuthenticationManager("dummy application Name");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInitialize_when_authenticationManager_is_null() throws Exception {
        Map<String, ?> shareState = new HashMap<String, Object>();
        Map<String, ?> options = new HashMap<String, Object>();
        options.put(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel(), null);
        //when
        userLoginModule.initialize(new Subject(), callbackHandler, shareState, options);
    }

    public void testInitialize_nominal_case() throws Exception {
        //given
        Map<String, ?> shareState = new HashMap<String, Object>();
        Map<String, Object> options = new HashMap<String, Object>();
        options.put(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel(), new MockAuthenticationManager(""));
        //when
        userLoginModule.initialize(new Subject(), callbackHandler, shareState, options);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testInitialize_when_options_are_null() throws Exception {
        Map<String, ?> shareState = new HashMap<String, Object>();
        Map<String, ?> options = null;
        //when
        userLoginModule.initialize(new Subject(), callbackHandler, shareState, options);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInitialize_when_callbackhandler_is_null() throws Exception {
        Map<String, ?> shareState = new HashMap<String, Object>();
        Map<String, Object> options = new HashMap<String, Object>();

        options.put(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel(), mockAuthenticationManager);
        //when
        userLoginModule.initialize(new Subject(), null, shareState, options);
    }


    @Test
    public void testLogin() throws Exception {
        initProperlyUserLoginmodule();
        mockUserLoginModule.login();
        verify(mockCallbackHandler).handle(any(Callback[].class));
    }

    private void initProperlyUserLoginmodule() {
        Map<String, ?> shareState = new HashMap<String, Object>();
        Map<String, Object> options = new HashMap<String, Object>();
        options.put(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel(), mockAuthenticationManager);
        mockUserLoginModule.initialize(new Subject(), mockCallbackHandler, shareState, options);
    }

    @Test
    public void testLogout() throws Exception {

    }

    @Test
    public void testAbort() throws Exception {

    }


    @Test
    public void testCommit_with_login_ok_set_to_false() throws Exception {
        //given
        Map<String, ?> shareState = new HashMap<String, Object>();
        Map<String, Object> options = new HashMap<String, Object>();
        options.put(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel(), mockAuthenticationManager);
        userLoginModule.loginOK = false;
        userLoginModule.initialize(new Subject(), mockCallbackHandler, shareState, options);
        userLoginModule.login();
        //when
        boolean commit = userLoginModule.commit();

        //then
        assertThat(commit, is(false));
    }

    @Test
    public void testCommit_without_credentials_and_principals() throws Exception {
        //given
        Map<String, ?> shareState = new HashMap<String, Object>();
        Map<String, Object> options = new HashMap<String, Object>();
        options.put(JGuardAuthenticationManagerMarkups.AUTHENTICATION_MANAGER.getLabel(), mockAuthenticationManager);
        Subject subject = new Subject();
        userLoginModule.initialize(subject, mockCallbackHandler, shareState, options);
        userLoginModule.login();
        //when
        boolean commit = userLoginModule.commit();
        Set<Object> publicCredentials = subject.getPublicCredentials();
        //then
        assertThat(commit, is(true));
        JGuardCredential jGuardCredential = new JGuardCredential(UserLoginModule.AUTHENTICATION_SCHEME_HANDLER_NAME, NAME_FRM_HOOK_FORM_SCHEME_HANDLER);
        assertThat(publicCredentials.contains(jGuardCredential), is(true));
    }
}
