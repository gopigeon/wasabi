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
package com.intuit.wasabi.userdirectory.impl;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import com.intuit.wasabi.authenticationobjects.UserInfo;
import com.intuit.wasabi.authenticationobjects.UserInfo.Username;
import com.intuit.wasabi.exceptions.AuthenticationException;
import com.intuit.wasabi.userdirectory.UserDirectory;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.LineNumberReader;
import java.util.List;

import static java.text.MessageFormat.format;

/**
 * Noop implementation for the UserDirectory, by default we will return super admin user
 */
public class DefaultUserDirectory implements UserDirectory {


    private final List<UserInfo> users;

    /**
     * @param users a list of user credentials
     */
    @Inject
    public DefaultUserDirectory(final @Named("authentication.users") List<UserInfo> users) {
        this.users = users;
    }

    /**
     * @param userEmail a user email address to check if it exists
     * @return a userinfo contain the user with that email address
     * @see UserDirectory#lookupUserByEmail(java.lang.String)
     */
    @Override
    public UserInfo lookupUserByEmail(final String userEmail) {

        for (UserInfo user : users) {
            if (user.getEmail().equals(userEmail)) {
                return user;
            }
        }

        throw new AuthenticationException(format("Email address does not exist: {0}", userEmail));
    }

    @Override
    public UserInfo lookupUser(final Username username) {
        final String usernameString = username.getUsername();

        for (UserInfo user : users) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }

        throw new AuthenticationException(format("Username does not exist: {0}", usernameString));
    }

    @Override
    public UserInfo addUser(String username, String password, String firstName, String lastName, Boolean writeToFile){
        UserInfo userInfo = new UserInfo.Builder(UserInfo.Username.valueOf(username))
                .withUserId(username)
                .withPassword(password)
                .withEmail(username)
                .withFirstName(firstName)
                .withLastName(lastName)
                .build();
        if (writeToFile) {
            writeToFile(username, firstName, lastName);
        }
        users.add(userInfo);
        return userInfo;
    }

    @Override
    public UserInfo getUserByEmail(final String userEmail) {

        for (UserInfo user : users) {
            if (user.getEmail().equals(userEmail)) {
                return user;
            }
        }
        return null;
    }

    private void writeToFile(String username, String firstName, String lastName) {
        File file = null;
        String line = "";
        String newLine = "";
        FileWriter writer;
        String path = "";
        path = "./../user-directory/src/main/resources/userDirectory.properties";
        file = new File(path);

        try(FileReader fr = new FileReader(file); LineNumberReader lnr = new LineNumberReader(fr) ) {

            while ((line = lnr.readLine()) != null) {
                if(line.startsWith("user.ids")){
                    line = line+":"+username;
                    newLine = newLine +line+ "\r\n";
                } else {
                    newLine = newLine +line+ "\r\n";
                }
            }
            newLine = newLine+"user."+username+":"+username+"::"+username+":"+firstName+":"+lastName + "\r\n";
            writer = new FileWriter(path);
            writer.write(newLine);
            writer.close();
        } catch (Exception e){
            e.printStackTrace();
            throw new AuthenticationException("Could not update properties file");

        }
    }
}
