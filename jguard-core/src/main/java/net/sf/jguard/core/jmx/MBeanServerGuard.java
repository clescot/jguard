/*
jGuard is a security framework based on top of jaas (java authentication and authorization security).
it is written for web applications, to resolve simply, access control problems.
version $Name$
http://sourceforge.net/projects/jguard/

Copyright (C) 2004  Charles GAY

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


jGuard project home page:
http://sourceforge.net/projects/jguard/

*/
package net.sf.jguard.core.jmx;

import net.sf.jguard.core.authorization.policy.LocalAccessController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.*;
import javax.management.loading.ClassLoaderRepository;
import javax.management.remote.MBeanServerForwarder;
import java.io.ObjectInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessControlException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */
 class MBeanServerGuard implements MBeanServerForwarder {
    private static final Logger logger = LoggerFactory.getLogger(MBeanServerGuard.class.getName());
    private MBeanServer mbs = null;
    private LocalAccessController accessController = null;
    public static final String ADD_NOTIFICATION_LISTENER = "addNotificationListener";
    public static final String INSTANTIATE = "instantiate";
    public static final String REGISTER_MBEAN = "registerMBean";
    public static final String REGISTER = "register";
    public static final String GET_CLASS_LOADER_FOR = "getClassLoaderFor";
    public static final String GET_CLASS_LOADER_REPOSITORY = "getClassLoaderRepository";
    public static final String GET_CLASS_LOADER = "getClassLoader";
    public static final String GET_ATTRIBUTE = "getAttribute";
    public static final String GET_DOMAINS = "getDomains";
    public static final String GET_MBEAN_INFO = "getMBeanInfo";
    public static final String GET_OBJECT_INSTANCE = "getObjectInstance";
    public static final String INVOKE = "invoke";
    public static final String IS_INSTANCE_OF = "isInstanceOf";
    public static final String QUERY_MBEANS = "queryMBeans";
    public static final String QUERY_NAMES = "queryNames";
    public  static final String REMOVE_NOTIFICATION_LISTENER = "removeNotificationListener";
    public static final String SET_ATTRIBUTE = "setAttribute";
    public static final String UNREGISTER_MBEAN = "unregisterMBean";

    public MBeanServerGuard(LocalAccessController lac) {
        accessController = lac;
    }

    public MBeanServer getMBeanServer() {
        return mbs;
    }

    public void setMBeanServer(MBeanServer mBeanServer) {
        mbs = mBeanServer;
    }

    public void addNotificationListener(ObjectName name,
                                        NotificationListener listener, NotificationFilter filter,
                                        Object handback) throws InstanceNotFoundException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, ADD_NOTIFICATION_LISTENER));
        mbs.addNotificationListener(name, listener, filter, handback);

    }

    public void addNotificationListener(ObjectName name, ObjectName listener,
                                        NotificationFilter filter, Object handback)
            throws InstanceNotFoundException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, ADD_NOTIFICATION_LISTENER));
        mbs.addNotificationListener(name, listener, filter, handback);
    }

    public ObjectInstance createMBean(String className, ObjectName name)
            throws ReflectionException, InstanceAlreadyExistsException,
            MBeanException,
            NotCompliantMBeanException {

        return createMBean(className, name, null, null);

    }

    public ObjectInstance createMBean(String className, ObjectName name,
                                      ObjectName loaderName) throws ReflectionException,
            InstanceAlreadyExistsException,
            MBeanException, NotCompliantMBeanException,
            InstanceNotFoundException {
        return createMBean(className, name, loaderName, null, null);
    }

    public ObjectInstance createMBean(String className, ObjectName name,
                                      Object[] params, String[] signature) throws ReflectionException,
            InstanceAlreadyExistsException,
            MBeanException, NotCompliantMBeanException {
        ObjectInstance oi = null;

        try {
            return createMBean(className, name, null, null, null);
        } catch (InstanceNotFoundException e) {
            logger.error(e.getMessage());
        }
        return oi;

    }

    public ObjectInstance createMBean(String className, ObjectName name,
                                      ObjectName loaderName, Object[] params, String[] signature)
            throws ReflectionException, InstanceAlreadyExistsException,
            MBeanException,
            NotCompliantMBeanException, InstanceNotFoundException {
        //instantiate permission check
        accessController.checkPermission(new MBeanPermission(className, null, null, INSTANTIATE));

        //register permission check
        accessController.checkPermission(new MBeanPermission(className, null, name, REGISTER_MBEAN));
        Class clazz = null;
        try {
            clazz = Thread.currentThread().getContextClassLoader().loadClass(className);
        } catch (ClassNotFoundException e) {
            logger.error(e.getMessage());
        }
        if (!clazz.getProtectionDomain().implies(new MBeanTrustPermission(REGISTER))) {
            throw new AccessControlException("registration denied");
        }

        if (name == null) {
            Class[] classes = new Class[signature.length];
            for (int i = 0; i < signature.length; i++) {
                String element = signature[i];
                try {
                    classes[i] = Thread.currentThread().getContextClassLoader().loadClass(element);
                } catch (ClassNotFoundException e) {
                    logger.error(e.getMessage());
                }
            }
            Constructor constructor;
            Object obj = null;
            try {
                constructor = clazz.getDeclaredConstructor(classes);
                obj = constructor.newInstance(params);
            } catch (SecurityException e) {
                logger.error(e.getMessage());
            } catch (NoSuchMethodException e) {
                logger.error(e.getMessage());
            } catch (IllegalArgumentException e) {
                logger.error(e.getMessage());
            } catch (InstantiationException e) {
                logger.error(e.getMessage());
            } catch (IllegalAccessException e) {
                logger.error(e.getMessage());
            } catch (InvocationTargetException e) {
                logger.error(e.getMessage());
            }

            MBeanRegistration mbeanReg = (MBeanRegistration) obj;
            try {
                name = mbeanReg.preRegister(mbs, null);
            } catch (Exception e) {
                logger.error(e.getMessage());
            }
            accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, REGISTER_MBEAN));
        }


        return mbs.createMBean(className, name);
    }

    public ObjectInputStream deserialize(ObjectName name, byte[] data)
            throws OperationsException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, GET_CLASS_LOADER_FOR));
        return mbs.deserialize(name, data);
    }

    public ObjectInputStream deserialize(String className, byte[] data)
            throws OperationsException, ReflectionException {
        accessController.checkPermission(new MBeanPermission(null, null, null, GET_CLASS_LOADER_REPOSITORY));
        return mbs.deserialize(className, data);
    }

    public ObjectInputStream deserialize(String className,
                                         ObjectName loaderName, byte[] data)
            throws OperationsException,
            ReflectionException {
        accessController.checkPermission(new MBeanPermission(getClassName(loaderName), null, loaderName, GET_CLASS_LOADER));
        return mbs.deserialize(className, loaderName, data);
    }

    public Object getAttribute(ObjectName name, String attribute)
            throws MBeanException, AttributeNotFoundException,
            InstanceNotFoundException, ReflectionException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), attribute, name, GET_ATTRIBUTE));
        return mbs.getAttribute(name, attribute);
    }

    public AttributeList getAttributes(ObjectName name, String[] attributes)
            throws InstanceNotFoundException, ReflectionException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, GET_ATTRIBUTE));
        AttributeList attList = mbs.getAttributes(name, attributes);
        for (int i = 0; i < attList.size(); i++) {
            Attribute att = (Attribute) attList.get(i);
            try {
                accessController.checkPermission(new MBeanPermission(getClassName(name), att.getName(), name, GET_ATTRIBUTE));
            } catch (AccessControlException ace) {
                attList.remove(att);
                i--;
            }
        }
        return attList;
    }

    public ClassLoader getClassLoader(ObjectName loaderName)
            throws InstanceNotFoundException {
        accessController.checkPermission(new MBeanPermission(getClassName(loaderName), null, loaderName, GET_CLASS_LOADER));
        return mbs.getClassLoader(loaderName);
    }

    public ClassLoader getClassLoaderFor(ObjectName mbeanName)
            throws InstanceNotFoundException {
        accessController.checkPermission(new MBeanPermission(getClassName(mbeanName), null, mbeanName, GET_CLASS_LOADER_FOR));
        return mbs.getClassLoaderFor(mbeanName);
    }

    public ClassLoaderRepository getClassLoaderRepository() {
        accessController.checkPermission(new MBeanPermission(null, null, null, GET_CLASS_LOADER_REPOSITORY));
        return mbs.getClassLoaderRepository();
    }

    public String getDefaultDomain() {
        return mbs.getDefaultDomain();
    }

    public String[] getDomains() {
        MBeanPermission perm = null;
        try {
            perm = new MBeanPermission(null, null, new ObjectName("*"), GET_DOMAINS);
        } catch (MalformedObjectNameException e) {
            logger.error(e.getMessage());
        } catch (NullPointerException e) {
            logger.error(e.getMessage());
        }
        accessController.checkPermission(perm);
        List<String> domainsList = Arrays.asList(mbs.getDomains());
        for (int i = 0; i < domainsList.size(); i++) {
            String domain = domainsList.get(i);
            try {
                accessController.checkPermission(new MBeanPermission(null, null, new ObjectName(domain + ":x=x"), GET_DOMAINS));
            } catch (AccessControlException ace) {
                domainsList.remove(domain);
                i--;
            } catch (MalformedObjectNameException e) {
                logger.error(e.getMessage());
            } catch (NullPointerException e) {
                logger.error(e.getMessage());
            }
        }
        return domainsList.toArray(new String[domainsList.size()]);
    }

    public Integer getMBeanCount() {
        return mbs.getMBeanCount();
    }

    public MBeanInfo getMBeanInfo(ObjectName name)
            throws InstanceNotFoundException, IntrospectionException,
            ReflectionException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, GET_MBEAN_INFO));
        return mbs.getMBeanInfo(name);
    }

    public ObjectInstance getObjectInstance(ObjectName name)
            throws InstanceNotFoundException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, GET_OBJECT_INSTANCE));
        return mbs.getObjectInstance(name);
    }

    public Object instantiate(String className) throws ReflectionException,
            MBeanException {
        accessController.checkPermission(new MBeanPermission(className, null, null, INSTANTIATE));
        return mbs.instantiate(className);
    }

    public Object instantiate(String className, ObjectName loaderName)
            throws ReflectionException, MBeanException,
            InstanceNotFoundException {
        accessController.checkPermission(new MBeanPermission(className, null, null, INSTANTIATE));
        return mbs.instantiate(className, loaderName);
    }

    public Object instantiate(String className, Object[] params,
                              String[] signature) throws ReflectionException, MBeanException {
        accessController.checkPermission(new MBeanPermission(className, null, null, INSTANTIATE));
        return mbs.instantiate(className, params, signature);
    }

    public Object instantiate(String className, ObjectName loaderName,
                              Object[] params, String[] signature) throws ReflectionException,
            MBeanException, InstanceNotFoundException {
        accessController.checkPermission(new MBeanPermission(className, null, null, INSTANTIATE));
        return mbs.instantiate(className, loaderName, params, signature);
    }

    public Object invoke(ObjectName name, String operationName,
                         Object[] params, String[] signature)
            throws InstanceNotFoundException, MBeanException,
            ReflectionException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), operationName, name, INVOKE));
        return mbs.invoke(name, operationName, params, signature);
    }

    public boolean isInstanceOf(ObjectName name, String className)
            throws InstanceNotFoundException {
        accessController.checkPermission(new MBeanPermission(className, null, name, IS_INSTANCE_OF));
        return mbs.isInstanceOf(name, className);
    }

    public boolean isRegistered(ObjectName name) {
        return mbs.isRegistered(name);
    }

    public Set<ObjectInstance> queryMBeans(ObjectName name, QueryExp query) {
        accessController.checkPermission(new MBeanPermission(null, null, name, QUERY_MBEANS));
        Set<ObjectInstance> mbeans = mbs.queryMBeans(name, query);

        Set<ObjectInstance> mbeansToRemove = new HashSet<ObjectInstance>();
        for (ObjectInstance oi : mbeans) {
            try {
                accessController.checkPermission(new MBeanPermission(oi.getClassName(), null, oi.getObjectName(), QUERY_MBEANS));
            } catch (AccessControlException ace) {
                mbeansToRemove.add(oi);
            }
        }
        mbeans.removeAll(mbeansToRemove);
        return mbeans;
    }

    public Set<ObjectName> queryNames(ObjectName name, QueryExp query) {
        accessController.checkPermission(new MBeanPermission(null, null, name, QUERY_NAMES));
        Set<ObjectName> mbeans = mbs.queryNames(name, query);
        Set<ObjectName> mbeansToRemove = new HashSet<ObjectName>();
        for (ObjectName on : mbeans) {
            try {
                accessController.checkPermission(new MBeanPermission(getClassName(on), null, on, QUERY_NAMES));
            } catch (AccessControlException ace) {
                mbeansToRemove.add(on);
            }
        }
        mbeans.removeAll(mbeansToRemove);

        return mbeans;
    }

    public ObjectInstance registerMBean(Object object, ObjectName name)
            throws InstanceAlreadyExistsException, MBeanRegistrationException,
            NotCompliantMBeanException {
        String className = null;
        try {
            className = mbs.getMBeanInfo(name).getClassName();
        } catch (InstanceNotFoundException e) {
            logger.error(e.getMessage());
        } catch (IntrospectionException e) {
            logger.error(e.getMessage());
        } catch (ReflectionException e) {
            logger.error(e.getMessage());
        }
        //instantiate permission check
        accessController.checkPermission(new MBeanPermission(className, null, null, INSTANTIATE));

        //register permission check
        if (name != null) {
            accessController.checkPermission(new MBeanPermission(className, null, name, REGISTER_MBEAN));
        } else {
            MBeanRegistration mbeanReg = (MBeanRegistration) object;
            try {
                name = mbeanReg.preRegister(mbs, null);
            } catch (Exception e) {
                logger.error(e.getMessage());
            }
            accessController.checkPermission(new MBeanPermission(className, null, name, REGISTER_MBEAN));
        }
        Class clazz;
        try {
            clazz = Thread.currentThread().getContextClassLoader().loadClass(className);
            if (!clazz.getProtectionDomain().implies(new MBeanTrustPermission(REGISTER))) {
                throw new AccessControlException("registration denied");
            }
        } catch (ClassNotFoundException e) {
            logger.error(e.getMessage());
        }

        return mbs.registerMBean(object, name);
    }

    public void removeNotificationListener(ObjectName name, ObjectName listener)
            throws InstanceNotFoundException, ListenerNotFoundException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, REMOVE_NOTIFICATION_LISTENER));
        mbs.removeNotificationListener(name, listener);

    }

    public void removeNotificationListener(ObjectName name,
                                           NotificationListener listener) throws InstanceNotFoundException,
            ListenerNotFoundException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, REMOVE_NOTIFICATION_LISTENER));
        mbs.removeNotificationListener(name, listener);

    }

    public void removeNotificationListener(ObjectName name,
                                           ObjectName listener, NotificationFilter filter, Object handback)
            throws InstanceNotFoundException, ListenerNotFoundException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, REMOVE_NOTIFICATION_LISTENER));
        mbs.removeNotificationListener(name, listener, filter, handback);

    }

    public void removeNotificationListener(ObjectName name,
                                           NotificationListener listener, NotificationFilter filter,
                                           Object handback) throws InstanceNotFoundException,
            ListenerNotFoundException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, REMOVE_NOTIFICATION_LISTENER));
        mbs.removeNotificationListener(name, listener, filter, handback);

    }

    public void setAttribute(ObjectName name, Attribute attribute)
            throws InstanceNotFoundException, AttributeNotFoundException,
            InvalidAttributeValueException, MBeanException, ReflectionException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), attribute.getName(), name, SET_ATTRIBUTE));
        mbs.setAttribute(name, attribute);
    }

    /**
     * we check firstly that the user has got the permission to act on the Mbean without referencing an operation or attribute;
     * and we check for each attribute if he has got the permission to update it.
     * if it hasn't got one of the required permissions, no update is done. Otherwise,
     * operation succeed.
     *
     * @param name
     * @param attributes
     * @return
     * @throws javax.management.InstanceNotFoundException
     *
     * @throws javax.management.ReflectionException
     *
     */
    public AttributeList setAttributes(ObjectName name, AttributeList attributes)
            throws InstanceNotFoundException, ReflectionException {

        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, SET_ATTRIBUTE));

        for (Object attribute : attributes) {
            Attribute att = (Attribute) attribute;
            accessController.checkPermission(new MBeanPermission(getClassName(name), att.getName(), name, SET_ATTRIBUTE));
        }

        return mbs.setAttributes(name, attributes);
    }

    public void unregisterMBean(ObjectName name)
            throws InstanceNotFoundException, MBeanRegistrationException {
        accessController.checkPermission(new MBeanPermission(getClassName(name), null, name, UNREGISTER_MBEAN));
        mbs.unregisterMBean(name);

    }

    private String getClassName(ObjectName name) {
        String className = null;
        try {
            className = mbs.getMBeanInfo(name).getClassName();
        } catch (InstanceNotFoundException e) {
            logger.error(e.getMessage());
        } catch (IntrospectionException e) {
            logger.error(e.getMessage());
        } catch (ReflectionException e) {
            logger.error(e.getMessage());
        }
        return className;
    }
}
