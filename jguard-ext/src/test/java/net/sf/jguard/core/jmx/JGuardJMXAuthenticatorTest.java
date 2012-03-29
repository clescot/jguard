package net.sf.jguard.core.jmx;

import com.google.inject.Module;
import com.mycila.testing.junit.MycilaJunitRunner;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.authentication.AuthenticationScope;
import net.sf.jguard.core.authentication.configuration.JGuardConfiguration;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.authorization.manager.AuthorizationManager;
import net.sf.jguard.core.authorization.policy.LocalAccessController;
import net.sf.jguard.core.authorization.policy.MultipleAppPolicy;
import net.sf.jguard.core.principals.RolePrincipal;
import net.sf.jguard.core.test.JGuardTest;
import net.sf.jguard.core.test.MockModule;
import net.sf.jguard.ext.authentication.manager.XmlAuthenticationManager;
import net.sf.jguard.ext.authorization.manager.XmlAuthorizationManager;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import javax.management.*;
import javax.management.remote.*;
import java.io.IOException;
import java.net.URL;
import java.security.AccessControlException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RunWith(MycilaJunitRunner.class)
public class JGuardJMXAuthenticatorTest extends JGuardTest{


    public static final String ADMIN_LOGIN = "admin";
    public static final String ADMIN_PASSWORD = "admin";
    public static final String DUMMY_LOGIN = "toto";
    public static final String DUMMY_PASSWORD = "toto";
    @Inject
    private JGuardConfiguration jGuardConfiguration;

    @Inject
    private MultipleAppPolicy multipleAppPolicy;
    
    @Inject
    private LocalAccessController localAccessController;


    @Inject
    private AuthorizationManager authorizationManager;
    private static final String GUEST_LOGIN = "guest";
    private static final String GUEST_PASSWORD = "guest";

    @Test(expected = IllegalArgumentException.class)
    public void testAuthenticateWithoutCredentials() throws Exception {
        JMXConnectorServer connectorServer = createMBeanServer(new JGuardJMXAuthenticator());
        JMXConnector cc = null;
       try {

        JMXServiceURL addr = connectorServer.getAddress();
        // Now make a connector client using the server's address without credentials....
        cc = JMXConnectorFactory.connect(addr);
        MBeanServerConnection mbsc = cc.getMBeanServerConnection();
        Set<ObjectInstance> instances = mbsc.queryMBeans(null,null);
            
         }catch(Exception e){
           System.out.println(e.getMessage());
           throw e;
        } finally {
            if (cc != null)
                cc.close();
            connectorServer.stop();
        }
    }


    @Test(expected = SecurityException.class)
    public void testAuthenticateWithDummyCredentials() throws Exception {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        JMXConnectorServer connectorServer = createMBeanServer(new JGuardJMXAuthenticator(JGuardTest.APPLICATION_NAME,cl,jGuardConfiguration));
        
        JMXConnector cc = null;
       try {

        JMXServiceURL addr = connectorServer.getAddress();
        // Now make a connector client using the server's address with dummy credentials
        Map<String,Object> env = new HashMap<String,Object>();
           String[] credentials = new String[] {DUMMY_LOGIN, DUMMY_PASSWORD};
           env.put(JMXConnector.CREDENTIALS, credentials);

        cc = JMXConnectorFactory.connect(addr,env);
        MBeanServerConnection mbsc = cc.getMBeanServerConnection();
        Set<ObjectInstance> instances = mbsc.queryMBeans(null,null);

         }catch(Exception e){
           System.out.println(e.getMessage());
           throw e;
        } finally {
            if (cc != null)
                cc.close();
            connectorServer.stop();
        }
    }
    private JMXConnector connectToMbeanServerAs(JMXConnectorServer connectorServer, String login, String password){

        JMXServiceURL addr = connectorServer.getAddress();
        // Now make a connector client using the server's address with dummy credentials
        Map<String,Object> env = new HashMap<String,Object>();
           String[] credentials = new String[] {login, password};
           env.put(JMXConnector.CREDENTIALS, credentials);

        try {
            return JMXConnectorFactory.connect(addr,env);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    @Test
    public void testAuthenticateWithRightCredentials() throws Throwable {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        JMXConnectorServer connectorServer = createMBeanServer(new JGuardJMXAuthenticator(JGuardTest.APPLICATION_NAME,cl,jGuardConfiguration));
        JMXConnector cc = connectToMbeanServerAs(connectorServer, ADMIN_LOGIN, ADMIN_PASSWORD);
       try {

         MBeanServerConnection mbsc = cc.getMBeanServerConnection();
         mbsc.queryMBeans(null,null);
       
         }catch(Throwable e){
           System.out.println(e.getMessage());
           throw e;
        } finally {
            if (cc != null)
                cc.close();
            connectorServer.stop();
        }
    }


    @Test(expected = AccessControlException.class)
    public void testUserAuthenticatedButNotAuthorized() throws Throwable {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        JMXConnectorServer connectorServer = createMBeanServer(new JGuardJMXAuthenticator(JGuardTest.APPLICATION_NAME,cl,jGuardConfiguration));
         connectorServer.setMBeanServerForwarder(new MBeanServerGuard(localAccessController));
        JMXConnector cc = connectToMbeanServerAs(connectorServer, GUEST_LOGIN, GUEST_PASSWORD);

       try {

         MBeanServerConnection mbsc = cc.getMBeanServerConnection();
         mbsc.queryMBeans(null,null);

         }catch(Throwable e){
           System.out.println(e.getMessage());
           throw e;
        } finally {
            if (cc != null)
                cc.close();
            connectorServer.stop();
        }
    }


     @Test
    public void testUserAuthenticatedAndAuthorized() throws Throwable {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        JMXConnectorServer connectorServer = createMBeanServer(new JGuardJMXAuthenticator(JGuardTest.APPLICATION_NAME,cl,jGuardConfiguration));
         connectorServer.setMBeanServerForwarder(new MBeanServerGuard(localAccessController));
        JMXConnector cc = connectToMbeanServerAs(connectorServer, ADMIN_LOGIN, ADMIN_PASSWORD);
         MBeanPermission permission = new MBeanPermission("*","*",null,MBeanServerGuard.QUERY_MBEANS);
         RolePrincipal seekPrincipal = findRole("admin");
        seekPrincipal.addPermission(permission);
        authorizationManager.updatePrincipal(seekPrincipal);

       try {

         MBeanServerConnection mbsc = cc.getMBeanServerConnection();
         mbsc.queryMBeans(null,null);

         }catch(Throwable e){
           System.out.println(e.getMessage());
           throw e;
        } finally {
            if (cc != null)
                cc.close();
            connectorServer.stop();
        }
    }

    private RolePrincipal findRole(String roleName) {
        List<RolePrincipal> principals = authorizationManager.listPrincipals();
        RolePrincipal seekPrincipal = null;
        for(RolePrincipal rolePrincipal:principals){
            if(rolePrincipal.getLocalName().equals(roleName)){
                seekPrincipal = rolePrincipal;
                break;
            }
        }
        return seekPrincipal;
    }


    private JMXConnectorServer createMBeanServer(JGuardJMXAuthenticator authenticator) throws IOException {
        System.setProperty(JGuardJMXAuthenticator.JGUARD_APPLICATION_NAME, JGuardTest.APPLICATION_NAME);
        MBeanServer mbs = MBeanServerFactory.createMBeanServer(JGuardTest.APPLICATION_NAME);
        //create connector's options
        Map opt=new HashMap();
        opt.put(JMXConnectorServer.AUTHENTICATOR,authenticator);
        //create JMXConnector
        JMXServiceURL url = new JMXServiceURL("service:jmx:rmi://");
        JMXConnectorServer connectorServer= JMXConnectorServerFactory.newJMXConnectorServer(url, opt, mbs);
        connectorServer.start();
        return connectorServer;
    }

    @Override
    @ModuleProvider
    protected AuthenticationManagerModule buildAuthenticationManagerModule() {
       return new AuthenticationManagerModule(APPLICATION_NAME, authenticationXmlFileLocation, XmlAuthenticationManager.class);
    }


    @ModuleProvider
    public Iterable<Module> providesModules() {
        URL url = Thread.currentThread().getContextClassLoader().getResource(".");
        List<Module> modules = super.providesModules(AuthenticationScope.LOCAL, true,
                url,
                XmlAuthorizationManager.class);
        modules.add(new MockModule());
        return modules;
    }
}
