package net.sf.jguard.ext.log.logback;

import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.Subject;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;

public class JGuardCredentialConverterTest {


    private static final String DUMMY_OPTION = "dummyOption";

    @Test
    public void test_Convert_With_Null_Argument() {
        JGuardCredentialConverter converter = new JGuardCredentialConverter();
        List<String> options = new ArrayList<String>();
        options.add(DUMMY_OPTION);
        converter.setOptionList(options);
        converter.convert(null);
    }


    @Test
    public void test_Convert_With_No_Authentication() {
        JGuardCredentialConverter converter = new JGuardCredentialConverter();
        List<String> options = new ArrayList<String>();
        options.add(DUMMY_OPTION);
        converter.setOptionList(options);
        String convertedString = converter.convert(null);
        Assert.assertTrue(JGuardCredentialConverter.UNAUTHENTICATED.equals(convertedString));
    }

    @Test
    public void test_Convert_With_Authentication_And_Empty_Subject() {

        Subject subject = new Subject();
        String convertedString = Subject.doAs(subject, new PrivilegedAction<String>() {
            public String run() {
                JGuardCredentialConverter converter = new JGuardCredentialConverter();
                List<String> options = new ArrayList<String>();
                options.add(DUMMY_OPTION);
                converter.setOptionList(options);
                return converter.convert(null);
            }
        });

        Assert.assertTrue(JGuardCredentialConverter.NO_IDENTITY_CREDENTIAL.equals(convertedString));
    }


    @Test(expected = IllegalArgumentException.class)
    public void test_Converter_With_Authentication_but_no_option() {
        Subject subject = new Subject();
        String convertedString = Subject.doAs(subject, new PrivilegedAction<String>() {
            public String run() {
                JGuardCredentialConverter converter = new JGuardCredentialConverter();
                List<String> options = new ArrayList<String>();
                converter.setOptionList(options);
                return converter.convert(null);
            }
        });
    }
}
