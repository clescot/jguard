package net.sf.jguard.core.authentication.callbacks;

import com.google.inject.Provider;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.util.ArrayList;
import java.util.Collection;

/**
 * provides callbacks which maps to  an authentication as a guest.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
public class GuestCallbacksProvider implements Provider<Collection<Callback>> {

    public static final String GUEST = "guest";

    public Collection<Callback> get() {
        Collection<Callback> callbacks = new ArrayList<Callback>();
        NameCallback nameCallback = new NameCallback("name", GUEST);
        nameCallback.setName(GUEST);
        callbacks.add(nameCallback);
        PasswordCallback passwordCallback = new PasswordCallback("password", true);
        passwordCallback.setPassword(GUEST.toCharArray());
        callbacks.add(passwordCallback);
        return callbacks;
    }
}
