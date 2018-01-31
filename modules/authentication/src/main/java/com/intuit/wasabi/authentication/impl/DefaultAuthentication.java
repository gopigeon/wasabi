/**
 * Copyright 2016 Intuit
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 *
 */
package com.intuit.wasabi.authentication.impl;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.Value;
import com.google.common.base.Optional;
import com.google.inject.Inject;
import com.google.inject.name.Named;
import com.intuit.wasabi.authentication.Authentication;
import com.intuit.wasabi.authentication.util.RandomStringGenerator;
import com.intuit.wasabi.authenticationobjects.LoginToken;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.intuit.wasabi.userdirectory.UserDirectory;
import org.slf4j.Logger;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.Optional.fromNullable;
import static com.intuit.autumn.utils.PropertyFactory.getProperty;
import static com.intuit.wasabi.authenticationobjects.LoginToken.withAccessToken;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Default authentication implementation
 */
public class DefaultAuthentication implements Authentication {

    private static final String SPACE = " ";
    private static final String SEMICOLON = ":";
    public static final String BASIC = "Basic";
    public static final String EMPTY = "";
    private static final Logger LOGGER = getLogger(DefaultAuthentication.class);
    private UserDirectory userDirectory;

    //Required for google login
    private static final JacksonFactory jacksonFactory = new JacksonFactory();
    private static final HttpTransport transport = new NetHttpTransport();
    private Pattern EMAIL_ADDRESS_REGEX;
    private GoogleIdTokenVerifier verifier;

    /**
     * @param userDirectory an instance of userDirectory that help us to lookup the user's info
     */
    @Inject
    public DefaultAuthentication(final UserDirectory userDirectory, @Named("google.client.id") String client_id, @Named("domain") String domain) {
        this.userDirectory = userDirectory;
        if (client_id != null && client_id.length() > 0){
            verifier = new GoogleIdTokenVerifier.Builder(transport, jacksonFactory)
                    .setAudience(Arrays.asList(client_id)).build();
            EMAIL_ADDRESS_REGEX = Pattern.compile("^[A-Z0-9._%+]+@"+domain+"$", Pattern.CASE_INSENSITIVE);


        }

    }

    /**
     * Attempts to return the LoginToken of the default user as if it was obtained via HTTP Basic authentication.
     *
     * @param authHeader the authentication header
     * @return a login token for this user (always)
     */
    @Override
    public LoginToken logIn(final String authHeader) {
        LOGGER.debug("Authentication header received as: {}", authHeader);

        UserCredential credential = parseUsernamePassword(fromNullable(authHeader));

        if (isBasicAuthenicationValid(credential)) {
            return withAccessToken(credential.toBase64Encode()).withTokenType(BASIC).build();
        } else {
            throw new AuthenticationException("Authentication login failed. Invalid Login Credential");
        }
    }

    /**
     * @param credential the user's credential
     * @return true if user token is valid, false otherwise
     */
    private boolean isBasicAuthenicationValid(final UserCredential credential) {
        // FIXME: this looks convoluted to me
        try {
            UserInfo userInfo = userDirectory.lookupUser(UserInfo.Username.valueOf(credential.username));

            return userInfo.getPassword().equals(credential.password);
        } catch (AuthenticationException ae) {
            LOGGER.error("Unable to lookup user", ae);
            return false;
        }
    }

    /**
     * Attempts to verify the user token retrieved via the {@link #logIn(String) logIn} method
     *
     * @param tokenHeader the token header
     * @return a login token for this user (always)
     */
    @Override
    public LoginToken verifyToken(final String tokenHeader) {
        LOGGER.debug("Authentication token received as: {}", tokenHeader);

        UserCredential credential = parseUsernamePassword(fromNullable(tokenHeader));

        if (isBasicAuthenicationValid(credential)) {
            return withAccessToken(credential.toBase64Encode()).withTokenType(BASIC).build();
        } else {
            throw new AuthenticationException("Authentication Token is not valid");
        }
    }

    /**
     * Attempts to return the LoginToken of the user after verifying the google access token belongs to narvar.
     *
     * @param token
     * @return a login token for this user (always)
     */
    @Override
    public LoginToken googleLogIn(final String token) {
        LOGGER.debug("Authentication header received as: {}", token);
        UserCredential credential = verifyTokenAndAddUser(token);
        if (isBasicAuthenicationValid(credential)) {
            return withAccessToken(credential.toBase64Encode()).withTokenType(BASIC).build();
        } else {
            throw new AuthenticationException("Authentication login failed. Invalid Login Credential");
        }
    }

    /**
     * Verifies the google token is properly signed or corrupted
     *
     * @param token
     * @return Credential for the user on successful verification
     * @throws AuthenticationException if not successful
     */
    private UserCredential verifyTokenAndAddUser(String token) {
        GoogleIdToken idToken = null;
        try {
            idToken = verifier.verify(token);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (idToken != null) {
            GoogleIdToken.Payload payload = idToken.getPayload();
            String email = payload.getEmail();
            String familyName = (String) payload.get("family_name");
            String givenName = (String) payload.get("given_name");

            UserInfo u = userDirectory.getUserByEmail(email);
            if (u == null){
                Matcher m = EMAIL_ADDRESS_REGEX.matcher(email);
                if(m.find()){
                    String password = RandomStringGenerator.getSaltString();
//                    String encryptPassword = CryptWithMD5.cryptWithMD5(password);
                    userDirectory.addUser(email, password, givenName, familyName);
                    UserCredential credential = new UserCredential(email, password);
                    return credential;
                } else {
                    throw new AuthenticationException("Authentication login failed. Only Narvar email Allowed");
                }
            } else {
                String password = RandomStringGenerator.getSaltString();
//                String encryptPassword = CryptWithMD5.cryptWithMD5(password);
                u.setPassword(password);
                UserCredential credential = new UserCredential(email, password);
                return credential;
            }
        } else {
            System.out.println("Invalid ID token.");
            throw new AuthenticationException("Authentication login failed. Invalid Token");
        }
    }

    /**
     * Just returns true. User need to present username and password for each action that requires credential
     * so logout does not do anything for basic authentication
     *
     * @param tokenHeader the token header
     * @return true
     */
    @Override
    public boolean logOut(final String tokenHeader) {
        return true;
    }

    /**
     * assumes the username is the email address that is used for this method
     *
     * @param userEmail the user mail
     * @return the UserInfo of the "admin" user
     */
    @Override
    public UserInfo getUserExists(final String userEmail) {
        LOGGER.debug("Authentication token received as: {}", userEmail);

        if (!isBlank(userEmail)) {
            return userDirectory.lookupUserByEmail(userEmail);
        } else {
            throw new AuthenticationException("user does not exists in system");
        }
    }

    /**
     * @param authHeader The http authroization header
     * @return UserCredential for the authHeader
     */
    private UserCredential parseUsernamePassword(final Optional<String> authHeader) {
        if (!authHeader.isPresent()) {
            throw new AuthenticationException("Null Authentication Header is not supported");
        }

        if (!authHeader.or(SPACE).contains(BASIC)) {
            throw new AuthenticationException("Only Basic Authentication is supported");
        }

        final String encodedUserPassword = authHeader.get().substring(authHeader.get().lastIndexOf(SPACE));
        String usernameAndPassword;

        LOGGER.trace("Base64 decoded username and password is: {}", encodedUserPassword);

        try {
            usernameAndPassword = new String(decodeBase64(encodedUserPassword.getBytes()));
        } catch (Exception e) {
            throw new AuthenticationException("error parsing username and password", e);
        }

        //Split username and password tokens
        String[] fields = usernameAndPassword.split(SEMICOLON);

        if (fields.length > 2) {
            throw new AuthenticationException("More than one username and password provided, or one contains ':'");
        } else if (fields.length < 2) {
            throw new AuthenticationException("Username or password are empty.");
        }

        if (isBlank(fields[0]) || isBlank(fields[1])) {
            throw new AuthenticationException("Username or password are empty.");
        }

        return new UserCredential(fields[0], fields[1]);
    }
}
