package net.sf.jguard.jee;

import com.google.inject.AbstractModule;
import com.google.inject.Module;
import com.google.inject.servlet.RequestScoped;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.authentication.AuthenticationScope;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.test.JGuardTest;
import net.sf.jguard.ext.authentication.manager.XmlAuthenticationManager;
import net.sf.jguard.ext.authorization.manager.XmlAuthorizationManager;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URL;
import java.util.List;

/**
 * base class for JGuard tests for the JEE environment.
 */
public abstract class JGuardJEETest extends JGuardTest {
    protected boolean propagateThrowable = true;
    protected HttpServletRequest httpServletRequest = new MockHttpServletRequest();
    protected HttpServletResponse httpServletResponse = new MockHttpServletResponse();
    protected FilterChain filterChain = new MockFilterChain();

    protected Iterable<Module> provideModules(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, final FilterChain filterChain) {
        final HttpServletRequest request = httpServletRequest;
        final HttpServletResponse response = httpServletResponse;
        URL applicationPath = Thread.currentThread().getContextClassLoader().getResource(".");
        List<Module> modules = super.providesModules(
                AuthenticationScope.LOCAL,
                propagateThrowable,
                applicationPath,
                XmlAuthorizationManager.class);
        modules.add(new AbstractModule() {

            @Override
            protected void configure() {
                bindScope(RequestScoped.class, new DummyRequestScope());
                bind(HttpServletRequest.class).toInstance(request);
                bind(HttpServletResponse.class).toInstance(response);
                bind(FilterChain.class).toInstance(filterChain);

            }
        });
        modules.add(new JEEModule());


        return modules;

    }

    @Override
    protected AuthenticationManagerModule buildAuthenticationManagerModule() {
        return new AuthenticationManagerModule(APPLICATION_NAME, authenticationXmlFileLocation, XmlAuthenticationManager.class);
    }

    @ModuleProvider
    public Iterable<Module> providesModules() {
        return provideModules(httpServletRequest, httpServletResponse, filterChain);
    }


}
