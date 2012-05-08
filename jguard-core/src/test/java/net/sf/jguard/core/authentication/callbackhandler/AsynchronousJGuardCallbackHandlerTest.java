package net.sf.jguard.core.authentication.callbackhandler;

import com.google.common.collect.Lists;
import net.sf.jguard.core.authentication.callbacks.AuthenticationChallengeForCallbackHandlerException;
import net.sf.jguard.core.authentication.callbacks.AuthenticationContinueForCallbackHandlerException;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockRequestAdapter;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.MockResponseAdapter;
import org.junit.Test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.mockito.Mockito.*;

public class AsynchronousJGuardCallbackHandlerTest {

    public static final String DUMMY_PROMPT = "dummyPrompt";

    @Test(expected = AuthenticationContinueForCallbackHandlerException.class)
    public void test_handle_answer_to_challenge_true_and_challenge_needed_true_implies_continue() throws Exception {
        //given
        MockRequestAdapter request = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter response = new MockResponseAdapter(new MockResponse());

        AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> authenticationSchemeHandler = mock(AuthenticationSchemeHandler.class);
        when(authenticationSchemeHandler.answerToChallenge(request, response)).thenReturn(true);
        when(authenticationSchemeHandler.challengeNeeded(request, response)).thenReturn(true);
        Collection<Class<? extends Callback>> callbackClasses = Lists.newArrayList();
        callbackClasses.add(NameCallback.class);
        when(authenticationSchemeHandler.getCallbackTypes()).thenReturn(callbackClasses);

        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);

        CallbackHandler mockCallbackHandler = new AsynchronousMockCallbackHandler(request, response, authenticationSchemeHandlers);
        List<Callback> callbackList = new ArrayList<Callback>();
        NameCallback nameCallback = new NameCallback(DUMMY_PROMPT);
        callbackList.add(nameCallback);
        Callback[] callbacks = callbackList.toArray(new Callback[callbackList.size()]);

        //when
        mockCallbackHandler.handle(callbacks);
        //then
        verify(authenticationSchemeHandler).buildChallenge(request, response);
    }


    @Test
    public void test_handle_answer_to_challenge_true_and_challenge_needed_false_implies_success() throws Exception {
        //given
        MockRequestAdapter request = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter response = new MockResponseAdapter(new MockResponse());

        AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> authenticationSchemeHandler = mock(AuthenticationSchemeHandler.class);
        when(authenticationSchemeHandler.answerToChallenge(request, response)).thenReturn(true);
        when(authenticationSchemeHandler.challengeNeeded(request, response)).thenReturn(false);
        Collection<Class<? extends Callback>> callbackClasses = Lists.newArrayList();
        callbackClasses.add(NameCallback.class);
        when(authenticationSchemeHandler.getCallbackTypes()).thenReturn(callbackClasses);

        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);

        CallbackHandler mockCallbackHandler = new AsynchronousMockCallbackHandler(request, response, authenticationSchemeHandlers);
        List<Callback> callbackList = new ArrayList<Callback>();
        NameCallback nameCallback = new NameCallback(DUMMY_PROMPT);
        callbackList.add(nameCallback);
        Callback[] callbacks = callbackList.toArray(new Callback[callbackList.size()]);

        //when
        mockCallbackHandler.handle(callbacks);

    }

    @Test
    public void test_handle_answer_to_challenge_false_and_challenge_needed_false_implies_success() throws Exception {
        //given
        MockRequestAdapter request = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter response = new MockResponseAdapter(new MockResponse());

        AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> authenticationSchemeHandler = mock(AuthenticationSchemeHandler.class);
        when(authenticationSchemeHandler.answerToChallenge(request, response)).thenReturn(false);
        when(authenticationSchemeHandler.challengeNeeded(request, response)).thenReturn(false);
        Collection<Class<? extends Callback>> callbackClasses = Lists.newArrayList();
        callbackClasses.add(NameCallback.class);
        when(authenticationSchemeHandler.getCallbackTypes()).thenReturn(callbackClasses);

        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);

        CallbackHandler mockCallbackHandler = new AsynchronousMockCallbackHandler(request, response, authenticationSchemeHandlers);
        List<Callback> callbackList = new ArrayList<Callback>();
        NameCallback nameCallback = new NameCallback(DUMMY_PROMPT);
        callbackList.add(nameCallback);
        Callback[] callbacks = callbackList.toArray(new Callback[callbackList.size()]);

        //when
        mockCallbackHandler.handle(callbacks);

    }


    @Test(expected = AuthenticationChallengeForCallbackHandlerException.class)
    public void test_handle_answer_to_challenge_false_and_challenge_needed_true_implies_failure() throws Exception {
        //given
        MockRequestAdapter request = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter response = new MockResponseAdapter(new MockResponse());

        AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> authenticationSchemeHandler = mock(AuthenticationSchemeHandler.class);
        when(authenticationSchemeHandler.answerToChallenge(request, response)).thenReturn(false);
        when(authenticationSchemeHandler.challengeNeeded(request, response)).thenReturn(true);
        Collection<Class<? extends Callback>> callbackClasses = Lists.newArrayList();
        callbackClasses.add(NameCallback.class);
        when(authenticationSchemeHandler.getCallbackTypes()).thenReturn(callbackClasses);

        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);

        CallbackHandler mockCallbackHandler = new AsynchronousMockCallbackHandler(request, response, authenticationSchemeHandlers);
        List<Callback> callbackList = new ArrayList<Callback>();
        NameCallback nameCallback = new NameCallback(DUMMY_PROMPT);
        callbackList.add(nameCallback);
        Callback[] callbacks = callbackList.toArray(new Callback[callbackList.size()]);

        //when
        mockCallbackHandler.handle(callbacks);
        //then
        verify(authenticationSchemeHandler).buildChallenge(request, response);
    }


    @Test(expected = AuthenticationChallengeForCallbackHandlerException.class)
    public void test_AsynchronousCallbackException_thrown_when_challenge_needed_and_asynchronous() throws UnsupportedCallbackException, IOException {
        //given
        MockRequestAdapter request = new MockRequestAdapter(new MockRequest());
        MockResponseAdapter response = new MockResponseAdapter(new MockResponse());

        AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter> authenticationSchemeHandler = mock(AuthenticationSchemeHandler.class);
        when(authenticationSchemeHandler.answerToChallenge(request, response)).thenReturn(false);
        when(authenticationSchemeHandler.challengeNeeded(request, response)).thenReturn(true);
        Collection<Class<? extends Callback>> callbackClasses = Lists.newArrayList();
        callbackClasses.add(NameCallback.class);
        when(authenticationSchemeHandler.getCallbackTypes()).thenReturn(callbackClasses);

        Collection<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>> authenticationSchemeHandlers = new ArrayList<AuthenticationSchemeHandler<MockRequestAdapter, MockResponseAdapter>>();
        authenticationSchemeHandlers.add(authenticationSchemeHandler);

        AsynchronousMockCallbackHandler mockCallbackHandler = new AsynchronousMockCallbackHandler(request, response, authenticationSchemeHandlers);
        List<Callback> callbackList = new ArrayList<Callback>();
        NameCallback nameCallback = new NameCallback(DUMMY_PROMPT);
        callbackList.add(nameCallback);
        Callback[] callbacks = callbackList.toArray(new Callback[callbackList.size()]);

        //when
        mockCallbackHandler.handle(callbacks);
    }
}
