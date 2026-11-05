package com.avash.identity.keycloak.sms;

import java.util.function.Function;

/**
 * SMS sign-in settings of a realm, written by the gateway as realm attributes ({@code iam.smslogin.*}).
 * Invalid or missing values fall back to safe defaults; the gateway validates what it writes.
 */
public record SmsLoginSettings(Mode mode, int codeLength, int codeLifetimeSeconds, int resendSeconds, int maxAttempts) {

    public static final String PREFIX = "iam.smslogin.";

    public enum Mode {
        OFF, PASSWORDLESS, SECOND_FACTOR;

        static Mode parse(String value) {
            if ("passwordless".equals(value)) return PASSWORDLESS;
            if ("second-factor".equals(value)) return SECOND_FACTOR;
            return OFF;
        }
    }

    public static SmsLoginSettings from(Function<String, String> attribute) {
        return new SmsLoginSettings(
                Mode.parse(attribute.apply(PREFIX + "mode")),
                number(attribute.apply(PREFIX + "code_length"), 4, 8, 6),
                number(attribute.apply(PREFIX + "ttl_seconds"), 60, 600, 120),
                number(attribute.apply(PREFIX + "resend_seconds"), 30, 300, 60),
                number(attribute.apply(PREFIX + "max_attempts"), 1, 10, 5));
    }

    private static int number(String value, int min, int max, int fallback) {
        if (value == null) return fallback;
        try {
            int n = Integer.parseInt(value.trim());
            return n < min || n > max ? fallback : n;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
