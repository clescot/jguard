package net.sf.jguard.core.authentication.credentials;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class JGuardCredentialTest {
    private static final String DUMMY_CREDENTIAL_NAME = "test";
    private static final String DIFFERENT_CREDENTIAL_NAME = "toto";

    private static final String DUMMY_CREDENTIAL_VALUE = "test2";
    private static final String DIFFERENT_CREDENTIAL_VALUE = "value3";

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

    @Test
    public void test_clone_credentialsSet_credentials_are_unlinked() throws Exception {
        //given
        Set<JGuardCredential> jGuardCredentials = new HashSet<JGuardCredential>();
        JGuardCredential jGuardCredential = getDummyCredential();
        jGuardCredentials.add(jGuardCredential);

        //when
        Set<JGuardCredential> cloneCredentials = JGuardCredential.cloneCredentialsSet(jGuardCredentials);
        jGuardCredential.setName(DIFFERENT_CREDENTIAL_NAME);
        jGuardCredential.setValue(DIFFERENT_CREDENTIAL_VALUE);

        JGuardCredential clone = cloneCredentials.iterator().next();
        //then
        assertThat(clone.getName(), is(not(jGuardCredential.getName())));
        assertThat(clone.getValue(), is(not(jGuardCredential.getValue())));
    }

    @Test
    public void test_clone_with_string_value() throws Exception {
        //given
        JGuardCredential dummyCredential = getDummyCredential();

        //when
        JGuardCredential clone = (JGuardCredential) dummyCredential.clone();
        clone.setName(DIFFERENT_CREDENTIAL_NAME);
        clone.setValue(DIFFERENT_CREDENTIAL_VALUE);

        //then
        assertThat(clone.getName(), is(not(dummyCredential.getName())));
        assertThat(clone.getValue(), is(not(dummyCredential.getValue())));
    }

    @Test
    public void test_clone_with_cloneable_value() throws Exception {
        //given
        JGuardCredential dummyCredential = getDummyCredential();
        dummyCredential.setValue(new HashSet<String>());
        //when
        JGuardCredential clone = (JGuardCredential) dummyCredential.clone();
        clone.setName(DIFFERENT_CREDENTIAL_NAME);
        clone.setValue(DIFFERENT_CREDENTIAL_VALUE);

        //then
        assertThat(clone.getName(), is(not(dummyCredential.getName())));
        assertThat(clone.getValue(), is(not(dummyCredential.getValue())));
    }

    @Test
    public void test_clone_with_null_value() throws Exception {
        //given
        JGuardCredential dummyCredential = getDummyCredential();
        dummyCredential.setValue(null);
        //when
        JGuardCredential clone = (JGuardCredential) dummyCredential.clone();
        clone.setName(DIFFERENT_CREDENTIAL_NAME);
        clone.setValue(DIFFERENT_CREDENTIAL_VALUE);

        //then
        assertThat(clone.getName(), is(not(dummyCredential.getName())));
        assertThat(clone.getValue(), is(not(dummyCredential.getValue())));
    }

    @Test(expected = CloneNotSupportedException.class)
    public void test_clone_with_non_cloneable_value() throws Exception {
        //given
        JGuardCredential dummyCredential = getDummyCredential();
        dummyCredential.setValue(new BigInteger("3"));
        //when
        JGuardCredential clone = (JGuardCredential) dummyCredential.clone();
        clone.setName(DIFFERENT_CREDENTIAL_NAME);
        clone.setValue(DIFFERENT_CREDENTIAL_VALUE);

        //then
        assertThat(clone.getName(), is(not(dummyCredential.getName())));
        assertThat(clone.getValue(), is(not(dummyCredential.getValue())));
    }

    private JGuardCredential getDummyCredential() {
        JGuardCredential jGuardCredential = new JGuardCredential();
        jGuardCredential.setName(DUMMY_CREDENTIAL_NAME);
        jGuardCredential.setValue(DUMMY_CREDENTIAL_VALUE);
        return jGuardCredential;
    }
}
