package net.sf.jguard.core.authentication.loginmodules;

import com.google.common.base.Strings;
import net.sf.jguard.core.authentication.callbacks.GuestCallbacksProvider;
import net.sf.jguard.core.util.CryptUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * should be inherited by classes which permits to query against different stores (database, xml..).
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class UserNamePasswordLoginModule extends UserLoginModule {
    private static final Logger logger = LoggerFactory.getLogger(UserNamePasswordLoginModule.class.getName());
    private static final String LOGIN = "login";
    private static final String PASSWORD = "password";

    @Override
    protected List<Callback> getCallbacks() {
        List<Callback> callbacks = new ArrayList<Callback>();
        callbacks.add(new NameCallback(LOGIN));
        callbacks.add(new PasswordCallback(PASSWORD, false));
        return callbacks;
    }

    /**
     * we ignore the PMD rule for the LoginException class,
     * which unfortunately hide the {@link java.security.GeneralSecurityException} constructor which
     * contains a {@link Throwable} parameter.
     *
     * @return
     * @throws LoginException
     */
    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public boolean login() throws LoginException {
        super.login();
        login = ((NameCallback) callbacks[0]).getName();
        password = ((PasswordCallback) callbacks[1]).getPassword();

        if (Strings.isNullOrEmpty(login)) {
            login = GuestCallbacksProvider.GUEST;
            password = GuestCallbacksProvider.GUEST.toCharArray();
        }

        if (GuestCallbacksProvider.GUEST.equals(login)
                && Arrays.equals(GuestCallbacksProvider.GUEST.toCharArray(), password)) {
            skipPasswordCheck = true;
        }

        if (password == null) {
            password = "".toCharArray();
            logger.debug(" password is null");
        } else {
            try {
                password = CryptUtils.cryptPassword(password);
            } catch (NoSuchAlgorithmException e) {
                throw new LoginException("Error encoding password (" + e.getMessage() + ")");
            }
            //remove the password from the PasswordCallback
            ((PasswordCallback) callbacks[1]).clearPassword();
            if (debug && logger.isDebugEnabled()) {
                logger.debug("login() - usernameFromForm=" + login);
                logger.debug("login() - passwordFromForm=" + new String(password));
            }

        }

        return true;
    }
}
