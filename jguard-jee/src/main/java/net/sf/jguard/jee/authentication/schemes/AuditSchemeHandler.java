package net.sf.jguard.jee.authentication.schemes;

import net.sf.jguard.core.authentication.callbacks.InetAddressCallback;
import net.sf.jguard.core.authentication.exception.AuthenticationException;
import net.sf.jguard.core.authentication.schemes.AuthenticationSchemeHandler;
import net.sf.jguard.core.authorization.permissions.JGPositivePermissionCollection;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.LanguageCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.PermissionCollection;
import java.util.*;

public abstract class AuditSchemeHandler<Req extends Request, Res extends Response> implements AuthenticationSchemeHandler<Req, Res> {
    private List<Class<? extends Callback>> callbackTypes = Arrays.asList(LanguageCallback.class, InetAddressCallback.class);
    private static final Logger logger = LoggerFactory.getLogger(AuditSchemeHandler.class);

    public AuditSchemeHandler(Map<String, String> parameters) {

    }

    public String getName() {
        return "AUDIT";
    }

    /**
     * @return {LanguageCallback} and {InetAddressCallback}.
     */
    public Collection<Class<? extends Callback>> getCallbackTypes() {
        return callbackTypes;
    }

    /**
     * no challenge are asked to the user. Only some information involved by
     * the communication and underlying technology are grabbed by this class.
     *
     * @return always true
     */
    public boolean answerToChallenge(Req request, Res response) {
        return false;
    }

    /**
     * like AuditSchemeHandler only records activity, it doesnt need to
     * request an authentication challenge.
     *
     * @return
     */
    public boolean impliesChallenge() {
        return false;
    }


    /**
     * no challenge are needed to collect required informations.
     *
     * @throws net.sf.jguard.core.authentication.exception.AuthenticationException
     *
     */
    public void buildChallenge(Req request, Res response) {

    }

    /**
     * no  Permission needs to be granted to the user to collect informations.
     *
     * @return empty PermissionCollection.
     */
    public PermissionCollection getGrantedPermissions() {
        return new JGPositivePermissionCollection();
    }

    /**
     * nothing to do when authentication succeed.
     *
     * @throws AuthenticationException
     */
    public void authenticationSucceed(Subject subject, Req request, Res response) {

    }

    /**
     * nothing to do when authentication failed.
     *
     * @throws AuthenticationException
     */
    public void authenticationFailed(Req request, Res response) {

    }

    protected abstract String getRemoteAddress(Req request);

    protected abstract String getRemoteHost(Req request);

    protected abstract Locale getLocale(Req request);


    public void handleSchemeCallbacks(Req request, Res response, Callback[] cbks) throws UnsupportedCallbackException {

        for (Callback cb : cbks) {
            if (cb instanceof InetAddressCallback) {
                String remoteAddress = getRemoteAddress(request);
                String remoteHost = getRemoteHost(request);
                InetAddressCallback inetAddressCallback = (InetAddressCallback) cb;
                inetAddressCallback.setHostAdress(remoteAddress);

                //the server is not configured to return the hostName.
                if (remoteAddress != null && remoteAddress.equals(remoteHost)) {
                    String resolvedHostName = remoteAddress;
                    try {
                        resolvedHostName = reverseDns(remoteAddress);
                    } catch (UnknownHostException uhe) {
                        logger.warn(" host bound to address " + remoteAddress + "cannot be resolved", uhe);
                        throw new UnsupportedCallbackException(cb, uhe.getMessage());
                    } catch (IOException ex) {
                        logger.error(ex.getMessage());
                        throw new UnsupportedCallbackException(cb, ex.getMessage());
                    }
                    inetAddressCallback.setHostName(resolvedHostName);
                }
            } else if (cb instanceof LanguageCallback) {
                LanguageCallback languageCallback = (LanguageCallback) cb;
                Locale locale = getLocale(request);
                languageCallback.setLocale(locale);
            }
        }
    }

    /**
     * return the host name related to the IP adress.
     * this method comes from <a href="http://www.oreillynet.com/onjava/blog/2005/11/reverse_dns_lookup_and_java.html">a blog entry about dnsjava</a>.
     *
     * @param hostIp Internet Protocol  adress
     * @return host name related to the hostIp parameter,
     *         or hostIp parameter if no nam eserver is found.
     */
    public static String reverseDns(String hostIp) throws IOException {

        Resolver res = new ExtendedResolver();
        Name name = ReverseMap.fromAddress(hostIp);
        int type = Type.PTR;
        int dclass = DClass.IN;
        Record rec = Record.newRecord(name, type, dclass);
        Message query = Message.newQuery(rec);
        Message response = res.send(query);

        Record[] answers = response.getSectionArray(Section.ANSWER);
        if (answers.length == 0) {
            return hostIp;
        } else {
            return answers[0].rdataToString();
        }
    }
}
