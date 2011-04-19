package net.sf.jguard.core.technology;

import com.google.inject.Inject;
import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.MockResponse;
import net.sf.jguard.core.lifecycle.Request;
import net.sf.jguard.core.lifecycle.Response;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class MockScopes extends AbstractScopes<MockRequest, MockResponse> implements StatefulScopes {

    private Map<String, Object> requestMap = new HashMap<String, Object>();
    private Map<String, Object> sessionMap = new HashMap<String, Object>();
    private Map<String, Object> applicationMap = new HashMap<String, Object>();
    private Map<String, String> initApplicationAttributes = new HashMap<String, String>();

    @Inject
    public MockScopes(Request<MockRequest> request, Response<MockResponse> response) {
        super(request, response);
    }


    public void setRequestAttribute(String key, Object value) {
        requestMap.put(key, value);
    }

    public Object getRequestAttribute(String key) {
        return requestMap.get(key);
    }

    public void removeRequestAttribute(String key) {
        requestMap.remove(key);
    }

    public void setApplicationAttribute(String key, Object value) {
        applicationMap.put(key, value);
    }

    public Object getApplicationAttribute(String key) {
        return applicationMap.get(key);
    }

    public void removeApplicationAttribute(String key) {
        applicationMap.remove(key);
    }

    /**
     * parameter defined for initialization purpose, reachable
     * at an application scope.
     *
     * @param key
     * @return value as a String
     */
    public String getInitApplicationAttribute(String key) {
        return initApplicationAttributes.get(key);
    }

    public void setSessionAttribute(String key, Object value) {
        sessionMap.put(key, value);
    }

    public Object getSessionAttribute(String key) {
        return sessionMap.get(key);
    }

    public Iterator<String> getSessionAttributeNames() {
        return sessionMap.keySet().iterator();
    }

    public void removeSessionAttribute(String key) {
        sessionMap.remove(key);
    }

    public void invalidateSession() {
        sessionMap.clear();
    }
}
