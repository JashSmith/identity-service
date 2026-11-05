package com.avash.identity.keycloak.sms;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

/**
 * State of one SMS code, kept server-side in Keycloak (authentication-session notes for the login page, single-use
 * objects for the token endpoint). Only a salted hash of the code is stored. Pure logic, so it is unit-tested.
 */
public final class SmsChallenge {

    public enum Outcome { VALID, WRONG, EXPIRED, TOO_MANY_ATTEMPTS, NO_CODE }

    static final String HASH = "avash.sms.hash";
    static final String SALT = "avash.sms.salt";
    static final String SENT_AT = "avash.sms.sent_at";
    static final String EXPIRES_AT = "avash.sms.expires_at";
    static final String ATTEMPTS = "avash.sms.attempts";
    static final String PHONE = "avash.sms.phone";
    static final String USER = "avash.sms.user";

    /** Every note this class writes (to copy them in and out of Keycloak's stores). */
    static final String[] KEYS = { HASH, SALT, SENT_AT, EXPIRES_AT, ATTEMPTS, PHONE, USER };

    private static final SecureRandom RANDOM = new SecureRandom();

    private SmsChallenge() {
    }

    /** A fresh code: returns the code to send and writes its state into {@code notes}. */
    public static String issue(Map<String, String> notes, String phone, String userId, int length, int lifetimeSeconds, long nowSeconds) {
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < length; i++) code.append(RANDOM.nextInt(10));
        byte[] saltBytes = new byte[16];
        RANDOM.nextBytes(saltBytes);
        String salt = HexFormat.of().formatHex(saltBytes);
        notes.put(HASH, hash(salt, code.toString()));
        notes.put(SALT, salt);
        notes.put(SENT_AT, Long.toString(nowSeconds));
        notes.put(EXPIRES_AT, Long.toString(nowSeconds + lifetimeSeconds));
        notes.put(ATTEMPTS, "0");
        notes.put(PHONE, phone == null ? "" : phone);
        notes.put(USER, userId == null ? "" : userId);
        return code.toString();
    }

    /** Checks {@code code} and counts the attempt in {@code notes}; a valid, expired or exhausted code is used up. */
    public static Outcome verify(Map<String, String> notes, String code, int maxAttempts, long nowSeconds) {
        if (!hasCode(notes)) return Outcome.NO_CODE;
        if (nowSeconds > number(notes.get(EXPIRES_AT))) {
            clear(notes);
            return Outcome.EXPIRED;
        }
        int attempts = (int) number(notes.get(ATTEMPTS)) + 1;
        String given = code == null ? "" : PhoneNumbers.latinDigits(code.trim());
        boolean valid = MessageDigest.isEqual(notes.get(HASH).getBytes(StandardCharsets.US_ASCII),
                hash(notes.get(SALT), given).getBytes(StandardCharsets.US_ASCII));
        if (valid) {
            clear(notes);
            return Outcome.VALID;
        }
        if (attempts >= maxAttempts) {
            clear(notes);
            return Outcome.TOO_MANY_ATTEMPTS;
        }
        notes.put(ATTEMPTS, Integer.toString(attempts));
        return Outcome.WRONG;
    }

    /** Seconds until another code may be sent (0 = now). */
    public static long resendIn(Map<String, String> notes, int resendSeconds, long nowSeconds) {
        String sentAt = notes.get(SENT_AT);
        if (sentAt == null || sentAt.isEmpty()) return 0;
        return Math.max(0, number(sentAt) + resendSeconds - nowSeconds);
    }

    /** Seconds the current code stays valid (0 = none or expired). */
    public static long expiresIn(Map<String, String> notes, long nowSeconds) {
        return hasCode(notes) ? Math.max(0, number(notes.get(EXPIRES_AT)) - nowSeconds) : 0;
    }

    public static boolean hasCode(Map<String, String> notes) {
        String hash = notes.get(HASH);
        return hash != null && !hash.isEmpty();
    }

    /** The code is used up; when it was sent stays, so the resend wait still applies. */
    public static void clear(Map<String, String> notes) {
        notes.put(HASH, "");
        notes.put(SALT, "");
        notes.put(EXPIRES_AT, "0");
        notes.put(ATTEMPTS, "0");
    }

    public static Map<String, String> copy(Map<String, String> notes) {
        return notes == null ? new HashMap<>() : new HashMap<>(notes);
    }

    private static long number(String value) {
        try {
            return value == null || value.isEmpty() ? 0 : Long.parseLong(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    static String hash(String salt, String code) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest((salt + ":" + code).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
