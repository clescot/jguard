package net.sf.jguard.core.authentication.credentials;

import org.junit.Assert;
import org.junit.Test;

public class JGuardCredentialTest {
    private static final String DUMMY_CREDENTIAL_NAME = "test";
    private static final String DUMMY_CREDENTIAL_VALUE = "test2";

    @Test
    public void testGetName() {
        JGuardCredential credential = new JGuardCredential(DUMMY_CREDENTIAL_NAME, DUMMY_CREDENTIAL_VALUE);
        Assert.assertEquals(DUMMY_CREDENTIAL_NAME, credential.getName());
    }

    @Test
    public void testGetValue() {
        JGuardCredential credential = new JGuardCredential(DUMMY_CREDENTIAL_NAME, DUMMY_CREDENTIAL_VALUE);
        Assert.assertEquals(DUMMY_CREDENTIAL_VALUE, credential.getValue());
    }
}
