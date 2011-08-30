package net.sf.jguard.core.authentication.jmx;

import com.google.inject.Module;
import com.mycila.testing.junit.MycilaJunitRunner;
import com.mycila.testing.plugin.guice.ModuleProvider;
import net.sf.jguard.core.authentication.AuthenticationScope;
import net.sf.jguard.core.authentication.configuration.JGuardConfiguration;
import net.sf.jguard.core.authentication.manager.AuthenticationManagerModule;
import net.sf.jguard.core.authentication.manager.MockAuthenticationManager;
import net.sf.jguard.core.authentication.manager.MockAuthenticationManagerModule;
import net.sf.jguard.core.authorization.manager.MockAuthorizationManager;
import net.sf.jguard.core.test.JGuardTest;
import net.sf.jguard.core.test.JGuardTestFiles;
import net.sf.jguard.core.test.MockModule;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import javax.management.MBeanServer;
import javax.management.MBeanServerConnection;
import javax.management.MBeanServerFactory;
import javax.management.ObjectInstance;
import javax.management.remote.*;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RunWith(MycilaJunitRunner.class)
public class JGuardJMXAuthenticatorTest extends JGuardTest{


    @Inject
    private JGuardConfiguration jGuardConfiguration;

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
            
           //String attr = (String) mbsc.getAttribute(objectName, "MyAttr");
           //mbsc.addNotificationListener(objectName, listener, filter, null)
         }catch(Exception e){
           System.out.println(e.getMessage());
           throw e;
        } finally {
            if (cc != null)
                cc.close();
            connectorServer.stop();
        }
    }


    @Test
    public void testAuthenticateWithDummyCredentials() throws Exception {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        JMXConnectorServer connectorServer = createMBeanServer(new JGuardJMXAuthenticator(JGuardTest.APPLICATION_NAME,cl,jGuardConfiguration));
        JMXConnector cc = null;
       try {

        JMXServiceURL addr = connectorServer.getAddress();
        // Now make a connector client using the server's address with dummy credentials
        Map<String,Object> env = new HashMap<String,Object>();
           String[] credentials = new String[] {"toto" ,"toto"};
           env.put(JMXConnector.CREDENTIALS, credentials);

        cc = JMXConnectorFactory.connect(addr,env);
        MBeanServerConnection mbsc = cc.getMBeanServerConnection();
        Set<ObjectInstance> instances = mbsc.queryMBeans(null,null);

           //String attr = (String) mbsc.getAttribute(objectName, "MyAttr");
           //mbsc.addNotificationListener(objectName, listener, filter, null)
         }catch(Exception e){
           System.out.println(e.getMessage());
           throw e;
        } finally {
            if (cc != null)
                cc.close();
            connectorServer.stop();
        }
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
       return new AuthenticationManagerModule(APPLICATION_NAME, authenticationXmlFileLocation, MockAuthenticationManager.class);
    }


    @ModuleProvider
    public Iterable<Module> providesModules() {
        URL url = Thread.currentThread().getContextClassLoader().getResource(".");
        List<Module> modules = super.providesModules(AuthenticationScope.LOCAL, true,
                url,
                MockAuthorizationManager.class);
        modules.add(new MockModule());
        return modules;
    }
}
