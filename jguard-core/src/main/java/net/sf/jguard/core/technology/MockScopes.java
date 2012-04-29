package net.sf.jguard.core.technology;

import net.sf.jguard.core.lifecycle.MockRequest;
import net.sf.jguard.core.lifecycle.Request;

import javax.inject.Inject;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class MockScopes extends AbstractScopes<MockRequest> implements StatefulScopes {


    private Map<String, Object> sessionMap = new HashMap<String, Object>();
    private Map<String, Object> applicationMap = new HashMap<String, Object>();

    @Inject
    public MockScopes(Request<MockRequest> request) {
        super(request);
    }


    public void setApplicationAttribute(String key, Object value) {
        applicationMap.put(key, value);
    }

    public Object getApplicationAttribute(String key) {
        return applicationMap.get(key);
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
