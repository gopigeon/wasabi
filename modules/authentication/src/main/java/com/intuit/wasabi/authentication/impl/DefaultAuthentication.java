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
import com.google.common.base.Optional;
import com.google.inject.Inject;
import com.google.inject.name.Named;
import com.intuit.wasabi.authentication.Authentication;
import com.intuit.wasabi.authentication.util.GoogleDirectory;
import com.intuit.wasabi.authentication.util.SecureRandomStringGenerator;
import com.intuit.wasabi.authenticationobjects.LoginToken;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.intuit.wasabi.userdirectory.UserDirectory;
import org.slf4j.Logger;
import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.Optional.fromNullable;
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

    //Required for google login
    private static final JacksonFactory jacksonFactory = new JacksonFactory();
    private static final HttpTransport transport = new NetHttpTransport();
    private static Pattern EMAIL_ADDRESS_REGEX;
    private static GoogleIdTokenVerifier verifier;

    private UserDirectory userDirectory;
    private String domain;
    private String authGroup;
    private GoogleDirectory googleDirectory;


    /**
     * @param userDirectory an instance of userDirectory that help us to lookup the user's info
     */
    @Inject
    public DefaultAuthentication(final UserDirectory userDirectory, @Named("google.client.id") String clientId, @Named("domain") String domain, @Named("auth_group") String authGroup, GoogleDirectory googleDirectory) {
        this.userDirectory = userDirectory;
        this.domain = domain;
        this.authGroup = authGroup;
        this.googleDirectory = googleDirectory;
        if (clientId != null && clientId.length() > 0){
            verifier = new GoogleIdTokenVerifier.Builder(transport, jacksonFactory)
                    .setAudience(Arrays.asList(clientId)).build();
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
     * @param access_token
     * @return a login token for this user (always)
     */
    @Override
    public LoginToken googleLogIn(String access_token) {
        LOGGER.debug("Authentication header received as: {}", access_token);
        UserCredential credential = verifyTokenAndAddUser(access_token);
        if (isBasicAuthenicationValid(credential)) {
            return withAccessToken(credential.toBase64Encode()).withTokenType(BASIC).build();
        } else {
            throw new AuthenticationException("Authentication login failed. Invalid Login Credential");
        }
    }

    /**
     * Verifies the google token is properly signed or corrupted
     *
     * @param access_token
     * @return Credential for the user on successful verification
     * @throws AuthenticationException if not successful
     */
    private UserCredential verifyTokenAndAddUser(String access_token) {
        GoogleIdToken idToken = null;
        try {
            idToken = verifier.verify(access_token);
//        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
            throw new AuthenticationException("Authentication login failed. Invalid Token");
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
                    if(checkUserBelongToGroup(authGroup, email)) {
                        String password = SecureRandomStringGenerator.getSaltString();
//                      String encryptPassword = CryptWithMD5.cryptWithMD5(password);
                        userDirectory.addUser(email, password, givenName, familyName, true);
                        UserCredential credential = new UserCredential(email, password);
                        return credential;
                    } else {
                        throw new AuthenticationException("Authentication login failed. Only user belonging to "+ authGroup +" group allowed");
                    }
                } else {
                    throw new AuthenticationException("Authentication login failed. Only "+ domain +" email allowed");
                }
            } else {
                String password = SecureRandomStringGenerator.getSaltString();
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

    public GoogleIdTokenVerifier getVerifier() {
        return verifier;
    }

    public static Pattern getEmailAddressRegex() {
        return EMAIL_ADDRESS_REGEX;
    }

//    /**
//     * Build and returns a Directory service object authorized with the service accounts
//     * that act on behalf of the given user.
//     *
//     * @param userEmail The email of the user. Needs permissions to access the Admin APIs.
//     * @return Directory service object that is ready to make requests.
//     */
//    public static Directory getDirectoryService(String userEmail) throws GeneralSecurityException,
//            IOException, URISyntaxException {
//        HttpTransport httpTransport = new NetHttpTransport();
//        JacksonFactory jsonFactory = new JacksonFactory();
//        Directory service = null;
//        GoogleCredential credential = new GoogleCredential.Builder()
//                .setTransport(httpTransport)
//                .setJsonFactory(jsonFactory)
//                .setServiceAccountId(SERVICE_ACCOUNT_EMAIL)
//                .setServiceAccountScopes(Arrays.asList(DirectoryScopes.ADMIN_DIRECTORY_GROUP_MEMBER, DirectoryScopes.ADMIN_DIRECTORY_GROUP, DirectoryScopes.ADMIN_DIRECTORY_USER))
//                .setServiceAccountUser(userEmail)
//                .setServiceAccountPrivateKeyFromP12File(
//                        new java.io.File(SERVICE_ACCOUNT_PKCS12_FILE_PATH))
//                .build();
//            service = new Directory.Builder(httpTransport, jsonFactory, null)
//                    .setHttpRequestInitializer(credential).build();
//        return service;
//    }

//
    public boolean checkUserBelongToGroup(String group, String email) {
        try {
            Boolean b = googleDirectory.service.members().hasMember(group, email).execute().getIsMember();
            return b;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

}
