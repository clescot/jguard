package net.sf.jguard.jsf.authentication.callbacks;

import net.sf.jguard.core.lifecycle.Request;
import org.apache.shale.test.mock.MockHttpServletRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import java.util.Locale;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JSFAuditSchemeHandlerTest {

    private JSFAuditSchemeHandler jsfAuditSchemeHandler;
    private Request<FacesContext> facesContextRequest;
    MockHttpServletRequest servletRequest;

    @Before
    public void setUp() {
        jsfAuditSchemeHandler = new JSFAuditSchemeHandler(null, null);
        final FacesContext facesContext = mock(FacesContext.class);
        ExternalContext externalContext = mock(ExternalContext.class);
        when(facesContext.getExternalContext()).thenReturn(externalContext);

        servletRequest = new MockHttpServletRequest();
        when(externalContext.getRequest()).thenReturn(servletRequest);

        facesContextRequest = new Request<FacesContext>() {
            public FacesContext get() {
                return facesContext;
            }
        };
    }


    @Test
    public void testGetLocaleIsNullReturnDefaultLocale() {

        Locale locale = jsfAuditSchemeHandler.getLocale(facesContextRequest);
        Assert.assertEquals(Locale.getDefault(), locale);
    }


    @Test
    public void testGetLocaleIsFrench() {
        servletRequest.setLocale(Locale.FRENCH);
        Locale locale = jsfAuditSchemeHandler.getLocale(facesContextRequest);
        Assert.assertEquals(Locale.FRENCH, locale);

    }


}
