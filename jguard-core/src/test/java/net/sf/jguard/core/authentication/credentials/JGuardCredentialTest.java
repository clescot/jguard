package net.sf.jguard.core.authentication.credentials;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;


@RunWith(Enclosed.class)
public class JGuardCredentialTest {
    private static final String DUMMY_CREDENTIAL_NAME = "test";
    private static final String DIFFERENT_CREDENTIAL_NAME = "toto";

    private static final String DUMMY_CREDENTIAL_VALUE = "test2";
    private static final String DIFFERENT_CREDENTIAL_VALUE = "value3";
    public static final String ANOTHER_CREDENTIAL_VALUE = "ANOTHER_CREDENTIAL_VALUE";
    private static final String ANOTHER_CREDENTIAL_NAME = "another credential value";


    public static class TestGetName {
        @Test
        public void testGetName() {
            JGuardCredential credential = new JGuardCredential(DUMMY_CREDENTIAL_NAME, DUMMY_CREDENTIAL_VALUE);
            Assert.assertEquals(DUMMY_CREDENTIAL_NAME, credential.getName());
        }


    }


    public static class TestGetValue {
        @Test
        public void testGetValue() {
            JGuardCredential credential = new JGuardCredential(DUMMY_CREDENTIAL_NAME, DUMMY_CREDENTIAL_VALUE);
            Assert.assertEquals(DUMMY_CREDENTIAL_VALUE, credential.getValue());
        }

    }

    public static class TestClone {
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
    }

    private static JGuardCredential getDummyCredential() {
        JGuardCredential jGuardCredential = new JGuardCredential();
        jGuardCredential.setName(DUMMY_CREDENTIAL_NAME);
        jGuardCredential.setValue(DUMMY_CREDENTIAL_VALUE);
        return jGuardCredential;
    }

    public static class TestEquals {
        @Test
        public void test_equals_with_same_credential() throws Exception {
            //given
            JGuardCredential dummyCredential = getDummyCredential();
            //when
            boolean equals = dummyCredential.equals(dummyCredential);
            //then
            assertThat(equals, is(true));
        }

        @Test
        public void test_equals_with_another_credential_with_same_name_and_value() throws Exception {
            //given
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(DUMMY_CREDENTIAL_NAME, DUMMY_CREDENTIAL_VALUE);
            //when
            boolean equals = dummyCredential.equals(jGuardCredential);
            //then
            assertThat(equals, is(true));
        }

        @Test
        public void test_equals_with_another_credential_with_same_name_and_different_value() throws Exception {
            //given
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(DUMMY_CREDENTIAL_NAME, ANOTHER_CREDENTIAL_VALUE);
            //when
            boolean equals = dummyCredential.equals(jGuardCredential);
            //then
            assertThat(equals, is(false));
        }

        @Test
        public void test_equals_with_another_credential_with_different_name_and_same_value() throws Exception {
            //given
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(ANOTHER_CREDENTIAL_NAME, DUMMY_CREDENTIAL_VALUE);
            //when
            boolean equals = dummyCredential.equals(jGuardCredential);
            //then
            assertThat(equals, is(false));
        }

        @Test
        public void test_equals_with_another_credential_with_different_name_and_value() throws Exception {
            //given
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(ANOTHER_CREDENTIAL_NAME, ANOTHER_CREDENTIAL_VALUE);
            //when
            boolean equals = dummyCredential.equals(jGuardCredential);
            //then
            assertThat(equals, is(false));
        }

        @Test
        public void test_equals_with_another_credential_with_null_name_and_value() throws Exception {
            //given
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(null, null);
            //when
            boolean equals = dummyCredential.equals(jGuardCredential);
            //then
            assertThat(equals, is(false));
        }

        @Test
        public void test_equals_with_initial_credential_with_null_name_and_value() throws Exception {
            //given
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(null, null);
            //when
            boolean equals = jGuardCredential.equals(dummyCredential);
            //then
            assertThat(equals, is(false));
        }


        @Test
        public void test_equals_with_another_Object_not_jguard_credential() throws Exception {
            //given
            JGuardCredential dummyCredential = getDummyCredential();
            //when
            boolean equals = dummyCredential.equals(DUMMY_CREDENTIAL_NAME);
            //then
            assertThat(equals, is(false));
        }

        @Test
        public void test_equals_with_all_name_and_values_are_null() throws Exception {
            //given
            JGuardCredential jGuardCredential = new JGuardCredential(null, null);
            JGuardCredential jGuardCredential2 = new JGuardCredential(null, null);
            //when
            boolean equals = jGuardCredential.equals(jGuardCredential2);
            //then
            assertThat(equals, is(true));
        }


    }

    public static class TestHashCode {

        @Test
        public void testHashCode_with_another_different_jguard_credential() throws Exception {
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(ANOTHER_CREDENTIAL_NAME, ANOTHER_CREDENTIAL_VALUE);
            //when
            int dummyHashCode = dummyCredential.hashCode();
            int jguardCredentialHashCode = jGuardCredential.hashCode();

            //then
            assertThat(dummyHashCode, Matchers.is(not(jguardCredentialHashCode)));
        }

        @Test
        public void testHashCode_with_another_different_jguard_credential_with_same_name_and_different_value() throws Exception {
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(DUMMY_CREDENTIAL_NAME, ANOTHER_CREDENTIAL_VALUE);
            //when
            int dummyHashCode = dummyCredential.hashCode();
            int jguardCredentialHashCode = jGuardCredential.hashCode();

            //then
            assertThat(dummyHashCode, Matchers.is(not(jguardCredentialHashCode)));
        }

        @Test
        public void testHashCode_with_another_different_jguard_credential_with_different_name_and_same_value() throws Exception {
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(ANOTHER_CREDENTIAL_NAME, DUMMY_CREDENTIAL_VALUE);
            //when
            int dummyHashCode = dummyCredential.hashCode();
            int jguardCredentialHashCode = jGuardCredential.hashCode();

            //then
            assertThat(dummyHashCode, Matchers.is(not(jguardCredentialHashCode)));
        }

        @Test
        public void testHashCode_with_another_different_jguard_credential_with_null_name_and_same_value() throws Exception {
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(null, DUMMY_CREDENTIAL_VALUE);
            //when
            int dummyHashCode = dummyCredential.hashCode();
            int jguardCredentialHashCode = jGuardCredential.hashCode();

            //then
            assertThat(dummyHashCode, Matchers.is(not(jguardCredentialHashCode)));
        }

        @Test
        public void testHashCode_with_another_different_jguard_credential_with_same_name_and_null_value() throws Exception {
            JGuardCredential dummyCredential = getDummyCredential();
            JGuardCredential jGuardCredential = new JGuardCredential(DUMMY_CREDENTIAL_NAME, null);
            //when
            int dummyHashCode = dummyCredential.hashCode();
            int jguardCredentialHashCode = jGuardCredential.hashCode();

            //then
            assertThat(dummyHashCode, Matchers.is(not(jguardCredentialHashCode)));
        }

        @Test
        public void testHashCode_with_another_different_jguard_credential_with_null_name_and_null_value() throws Exception {
            JGuardCredential dummyCredential = getDummyCredential();
            dummyCredential.setName(null);
            dummyCredential.setValue(null);
            JGuardCredential jGuardCredential = new JGuardCredential(null, null);
            //when
            int dummyHashCode = dummyCredential.hashCode();
            int jguardCredentialHashCode = jGuardCredential.hashCode();

            //then
            assertThat(dummyHashCode, Matchers.is(jguardCredentialHashCode));
        }
    }

    public static class TestToString {

        @Test
        public void testTOString_with_null_values() throws Exception {
            //given
            JGuardCredential jGuardCredential = new JGuardCredential(null, null);
            //when
            String toString = jGuardCredential.toString();
            //then
            assertThat(toString, is(not(nullValue())));
        }


        @Test
        public void testTOString_with_nominal_case() throws Exception {
            //given
            JGuardCredential jGuardCredential = getDummyCredential();
            //when
            String toString = jGuardCredential.toString();
            //then
            assertThat(toString, is(not(nullValue())));
        }
    }
}
