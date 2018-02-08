package com.intuit.wasabi.authentication.util;

import java.security.SecureRandom;

public  class SecureRandomStringGenerator {
    static String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@*$";
    public static String getSaltString() {
        StringBuilder salt = new StringBuilder();
        SecureRandom rnd = new SecureRandom();
        while (salt.length() < 8) { // length of the random string.
            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
            salt.append(SALTCHARS.charAt(index));
        }
        String saltStr = salt.toString();
        return saltStr;
    }
}
