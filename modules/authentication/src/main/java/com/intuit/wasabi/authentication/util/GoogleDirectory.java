package com.intuit.wasabi.authentication.util;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.admin.directory.Directory;
import com.google.api.services.admin.directory.DirectoryScopes;

import java.io.File;
import java.util.Arrays;

public class GoogleDirectory {

    private static GoogleDirectory single_instance = null;
    private static final String userEmail = "shivam@gopigeon.in";
    private static final String SERVICE_ACCOUNT_EMAIL = "wasabi-gsuite@wasabi-195410.iam.gserviceaccount.com";
    private static final String SERVICE_ACCOUNT_PKCS12_FILE_PATH = "modules/authentication/src/main/resources/wasabi-service-account-private-key.p12";

    public Directory service = null;

    private GoogleDirectory()
    {
        try {
            HttpTransport httpTransport = new NetHttpTransport();
            JacksonFactory jsonFactory = new JacksonFactory();
            GoogleCredential credential = new GoogleCredential.Builder()
                    .setTransport(httpTransport)
                    .setJsonFactory(jsonFactory)
                    .setServiceAccountId(SERVICE_ACCOUNT_EMAIL)
                    .setServiceAccountScopes(Arrays.asList(DirectoryScopes.ADMIN_DIRECTORY_GROUP_MEMBER, DirectoryScopes.ADMIN_DIRECTORY_GROUP, DirectoryScopes.ADMIN_DIRECTORY_USER))
                    .setServiceAccountUser(userEmail)
                    .setServiceAccountPrivateKeyFromP12File(
                            new java.io.File(SERVICE_ACCOUNT_PKCS12_FILE_PATH))
                    .build();
            service = new Directory.Builder(httpTransport, jsonFactory, null)
                    .setHttpRequestInitializer(credential).build();
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    public static GoogleDirectory getInstance()
    {
        if (single_instance == null)
            single_instance = new GoogleDirectory();

        return single_instance;
    }
}
