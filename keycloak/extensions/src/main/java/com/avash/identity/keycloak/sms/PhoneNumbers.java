package com.avash.identity.keycloak.sms;

/** Iranian mobile numbers in any common spelling (09.., 989.., +989.., 00989.., Persian or Arabic digits). Same rules as the gateway. */
public final class PhoneNumbers {

    /** User attribute holding the normalised number (+989XXXXXXXXX); written only by the gateway. */
    public static final String ATTRIBUTE = "phone_number";

    private PhoneNumbers() {
    }

    /** Returns +989XXXXXXXXX, or null when the text is not an Iranian mobile number. */
    public static String normalize(String text) {
        if (text == null || text.isBlank()) return null;
        StringBuilder digits = new StringBuilder();
        for (char c : latinDigits(text.trim()).toCharArray()) {
            if (c >= '0' && c <= '9') digits.append(c);
            else if (c == ' ' || c == '-' || c == '(' || c == ')' || c == '+') continue;
            else return null;
        }
        String d = digits.toString();
        if (d.startsWith("0098")) d = d.substring(4);
        else if (d.startsWith("98") && d.length() == 12) d = d.substring(2);
        else if (d.startsWith("0")) d = d.substring(1);
        return d.length() == 10 && d.charAt(0) == '9' ? "+98" + d : null;
    }

    /** Persian and Arabic digits as ASCII digits (numbers and codes typed on a Persian keyboard). */
    public static String latinDigits(String text) {
        StringBuilder b = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            if (c >= '۰' && c <= '۹') b.append((char) ('0' + (c - '۰')));
            else if (c >= '٠' && c <= '٩') b.append((char) ('0' + (c - '٠')));
            else b.append(c);
        }
        return b.toString();
    }

    /** 0912***4567: enough for the user to recognise their number on the page, not enough to collect it. */
    public static String mask(String normalized) {
        if (normalized == null || normalized.length() != 13) return "***";
        return "0" + normalized.substring(3, 6) + "***" + normalized.substring(9);
    }
}
