package net.sf.jguard.core;

import com.google.inject.AbstractModule;

/**
 * Guice module dedicated to set bindings to the Filterchain implementation (i.e, PolicyEnforcementPoint).
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class FilterChainModule extends AbstractModule {

    private boolean propagateThrowable;


    /**
     * @param propagateThrowable
     */
    public FilterChainModule(boolean propagateThrowable) {
        this.propagateThrowable = propagateThrowable;
    }

    @Override
    protected void configure() {

        bind(boolean.class).toInstance(propagateThrowable);
    }

}
