package net.sf.jguard.jee;

import org.junit.Test;

/**
 * TestCase for callers of PolicyEnforcementPoint like AccessFilter
 * and AccessListener.
 *
 * @author <a href="mailto:diabolo512@users.sourceforge.net">Charles Gay</a>
 */

public interface SecurityTestCase {

    @Test
    void testAccessToAuthorizedResourceGrantedToGuestSubject() throws Exception;

    @Test
    void testAccessToUnauthorizedResourceWithNoSubject() throws Exception;

    @Test
    void testAccessToUnauthorizedResourceWithSubject() throws Exception;

    @Test
    void testUnsuccessfulAuthentication() throws Exception;

    @Test
    void testSuccessFulAuthentication() throws Exception;

    @Test
    void testAccessToAuthorizedResourceWithSubject() throws Exception;


    @Test
    void testAccessToAuthorizedResourceWithNoSubject();
}
