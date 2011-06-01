package net.sf.jguard.core.jmx;

import javax.inject.Inject;
import com.google.inject.Provider;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * provide a {@link java.rmi.registry.Registry} instance.
 */
class RegistryProvider implements Provider<Registry> {
    private String rmiRegistryHost;
    private int rmiRegistryPort;

    @Inject
    public RegistryProvider(@RmiRegistryHost String rmiRegistryHost, @RmiRegistryPort int rmiRegistryPort) {
        this.rmiRegistryHost = rmiRegistryHost;
        this.rmiRegistryPort = rmiRegistryPort;
    }

    public Registry get() {
        try {
            return LocateRegistry.getRegistry(rmiRegistryHost, rmiRegistryPort);
        } catch (RemoteException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }
}
