package net.sf.jguard.core.lifecycle;

import javax.inject.Inject;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Lescot</a>
 */
public class MockRequestAdapter implements StatefulRequest<MockRequest> {

    private Map<String, Object> sessionMap = new HashMap<String, Object>();
    private MockRequest mockRequest;


    @Inject
    public MockRequestAdapter(MockRequest mockRequest) {
        this.mockRequest = mockRequest;
    }

    public MockRequest get() {
        return mockRequest;
    }

    public void setRequestAttribute(String key, Object value) {
        mockRequest.setRequestAttribute(key, value);
    }

    public Object getRequestAttribute(String key) {
        return mockRequest.getRequestAttribute(key);
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
