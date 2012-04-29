package net.sf.jguard.core.lifecycle;

import java.util.Iterator;

public interface StatefulRequest<T> extends Request<T> {
    void setSessionAttribute(String key, Object value);


    /**
     * return a object bound to the specified key.
     *
     * @param key
     * @return
     */
    Object getSessionAttribute(String key);

    /**
     * return an iterator of the key string, identifying the object bound to them.
     *
     * @return
     */
    Iterator<String> getSessionAttributeNames();

    /**
     * remove one attribute present in the session.
     *
     * @param key
     */
    void removeSessionAttribute(String key);

    /**
     * clear all content bound to this session.
     */
    void invalidateSession();

}
