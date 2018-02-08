package com.intuit.wasabi.authentication.impl;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.intuit.wasabi.authentication.AuthenticationModule;
import com.intuit.wasabi.authentication.util.SecureRandomStringGenerator;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.intuit.wasabi.userdirectory.UserDirectoryModule;
import org.junit.Before;
import org.junit.Test;
import java.io.InputStream;
import java.util.Properties;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class GoogleLoginTest {

    private DefaultAuthentication defaultGoogleAuthentication = null;
    private Properties p;

    @Before
    public void setUp() throws Exception {
        Injector injector = Guice.createInjector(new UserDirectoryModule(), new AuthenticationModule());
        defaultGoogleAuthentication = injector.getInstance(DefaultAuthentication.class);
        InputStream is = GoogleLoginTest.class.getClassLoader().getResourceAsStream("authentication.properties");
        p = new Properties();
        p.load(is);
        assertNotNull(defaultGoogleAuthentication);
    }

    @Test
    public void testGoogleVerifier() {
        assertNotNull(defaultGoogleAuthentication.getVerifier());
    }

    @Test
    public void testEmailRegex() {
        String domain = p.getProperty("domain");
        String testEmail = "donotpassemail@x"+domain;
        assertNotNull(defaultGoogleAuthentication.getEmailAddressRegex());
        Boolean b = defaultGoogleAuthentication.getEmailAddressRegex().matcher(testEmail).find();
        assertFalse(b);
        testEmail = "passemail@"+domain;
        b = defaultGoogleAuthentication.getEmailAddressRegex().matcher(testEmail).find();
        assertTrue(b);
    }

    @Test(expected = AuthenticationException.class)
    public void testInvalidTokenException(){
        String dummy_wrong_access_token = "thisisawrongtoken";
        defaultGoogleAuthentication.googleLogIn(dummy_wrong_access_token);
    }

    @Test
    public void paaswordGenerator(){
        String password = SecureRandomStringGenerator.getSaltString();
        assertNotNull(password);
        assertTrue(password.length() == 8);
    }
}

