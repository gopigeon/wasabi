package com.intuit.wasabi.authentication.util;

import java.util.Random;

public  class RandomStringGenerator {
    static String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@*$";

    public static String getSaltString() {
        StringBuilder salt = new StringBuilder();
        Random rnd = new Random();
        while (salt.length() < 8) { // length of the random string.
            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
            salt.append(SALTCHARS.charAt(index));
        }
        String saltStr = salt.toString();
        return saltStr;

    }
}
