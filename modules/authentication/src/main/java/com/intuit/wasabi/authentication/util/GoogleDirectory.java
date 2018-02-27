package com.intuit.wasabi.authentication.util;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.admin.directory.Directory;
import com.google.api.services.admin.directory.DirectoryScopes;
import com.google.inject.Inject;
import com.google.inject.name.Named;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class GoogleDirectory {

//    private String user_email;
//    private static final String SERVICE_ACCOUNT_EMAIL = "wasabi-gsuite@wasabi-195410.iam.gserviceaccount.com";
    private static final String SERVICE_ACCOUNT_PKCS12_FILE_PATH = "./../wasabi.p12";
    public Directory service = null;
    public String error = null;

    @Inject
    public GoogleDirectory(@Named("user_email") String user_email, @Named("service_account_email") String service_account_email)
    {
        try {
            HttpTransport httpTransport = new NetHttpTransport();
            JacksonFactory jsonFactory = new JacksonFactory();
            GoogleCredential credential = new GoogleCredential.Builder()
                    .setTransport(httpTransport)
                    .setJsonFactory(jsonFactory)
                    .setServiceAccountId(service_account_email)
                    .setServiceAccountScopes(Arrays.asList(DirectoryScopes.ADMIN_DIRECTORY_GROUP_MEMBER, DirectoryScopes.ADMIN_DIRECTORY_GROUP, DirectoryScopes.ADMIN_DIRECTORY_USER))
                    .setServiceAccountUser(user_email)
                    .setServiceAccountPrivateKeyFromP12File(
                            new File(SERVICE_ACCOUNT_PKCS12_FILE_PATH))
                    .build();
            service = new Directory.Builder(httpTransport, jsonFactory, null)
                    .setHttpRequestInitializer(credential).build();
        } catch (Exception e){
            e.printStackTrace();
            error = e.toString();
        }
    }


}
