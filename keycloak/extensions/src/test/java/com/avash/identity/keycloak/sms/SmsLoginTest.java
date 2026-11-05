package com.avash.identity.keycloak.sms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SmsLoginTest {

    @Test
    void numbers_in_every_common_spelling_become_one_form() {
        for (String typed : new String[] { "09121234567", "9121234567", "989121234567", "+989121234567", "00989121234567",
                "۰۹۱۲۱۲۳۴۵۶۷", "٠٩١٢١٢٣٤٥٦٧", "0912 123 4567", "(0912) 123-4567" }) {
            assertEquals("+989121234567", PhoneNumbers.normalize(typed), typed);
        }
        for (String typed : new String[] { null, "", "02112345678", "0912123456", "091212345678", "abc", "0912123456x" }) {
            assertNull(PhoneNumbers.normalize(typed), String.valueOf(typed));
        }
        assertEquals("0912***4567", PhoneNumbers.mask("+989121234567"));
        assertEquals("***", PhoneNumbers.mask(null));
    }

    @Test
    void settings_fall_back_to_safe_defaults() {
        Map<String, String> attributes = new HashMap<>();
        SmsLoginSettings defaults = SmsLoginSettings.from(attributes::get);
        assertEquals(SmsLoginSettings.Mode.OFF, defaults.mode());
        assertEquals(6, defaults.codeLength());
        assertEquals(120, defaults.codeLifetimeSeconds());

        attributes.put("iam.smslogin.mode", "passwordless");
        attributes.put("iam.smslogin.code_length", "5");
        attributes.put("iam.smslogin.ttl_seconds", "100000");
        attributes.put("iam.smslogin.max_attempts", "x");
        SmsLoginSettings settings = SmsLoginSettings.from(attributes::get);
        assertEquals(SmsLoginSettings.Mode.PASSWORDLESS, settings.mode());
        assertEquals(5, settings.codeLength());
        assertEquals(120, settings.codeLifetimeSeconds());
        assertEquals(5, settings.maxAttempts());

        attributes.put("iam.smslogin.mode", "second-factor");
        assertEquals(SmsLoginSettings.Mode.SECOND_FACTOR, SmsLoginSettings.from(attributes::get).mode());
        attributes.put("iam.smslogin.mode", "SECOND-FACTOR");
        assertEquals(SmsLoginSettings.Mode.OFF, SmsLoginSettings.from(attributes::get).mode());
    }

    @Test
    void a_code_is_valid_once_and_only_its_hash_is_stored() {
        Map<String, String> notes = new HashMap<>();
        String code = SmsChallenge.issue(notes, "+989121234567", "u1", 6, 120, 1000);

        assertEquals(6, code.length());
        assertFalse(notes.containsValue(code));
        assertEquals(SmsChallenge.Outcome.VALID, SmsChallenge.verify(notes, code, 5, 1010));
        assertEquals(SmsChallenge.Outcome.NO_CODE, SmsChallenge.verify(notes, code, 5, 1011));
        assertEquals("u1", notes.get(SmsChallenge.USER));
    }

    @Test
    void persian_digits_in_the_typed_code_are_accepted() {
        Map<String, String> notes = new HashMap<>();
        String code = SmsChallenge.issue(notes, "+989121234567", "u1", 6, 120, 1000);
        StringBuilder persian = new StringBuilder();
        for (char c : code.toCharArray()) persian.append((char) ('۰' + (c - '0')));

        assertEquals(SmsChallenge.Outcome.VALID, SmsChallenge.verify(notes, " " + persian + " ", 5, 1001));
    }

    @Test
    void wrong_codes_are_counted_and_the_last_allowed_attempt_uses_the_code_up() {
        Map<String, String> notes = new HashMap<>();
        String code = SmsChallenge.issue(notes, "+989121234567", "u1", 6, 120, 1000);
        String wrong = code.equals("000000") ? "111111" : "000000";

        assertEquals(SmsChallenge.Outcome.WRONG, SmsChallenge.verify(notes, wrong, 3, 1001));
        assertEquals(SmsChallenge.Outcome.WRONG, SmsChallenge.verify(notes, wrong, 3, 1002));
        assertEquals(SmsChallenge.Outcome.TOO_MANY_ATTEMPTS, SmsChallenge.verify(notes, wrong, 3, 1003));
        assertEquals(SmsChallenge.Outcome.NO_CODE, SmsChallenge.verify(notes, code, 3, 1004));
    }

    @Test
    void an_expired_code_is_refused_and_the_resend_wait_is_kept() {
        Map<String, String> notes = new HashMap<>();
        String code = SmsChallenge.issue(notes, "+989121234567", "u1", 6, 120, 1000);

        assertEquals(60, SmsChallenge.resendIn(notes, 60, 1000));
        assertEquals(20, SmsChallenge.resendIn(notes, 60, 1040));
        assertEquals(80, SmsChallenge.expiresIn(notes, 1040));
        assertEquals(SmsChallenge.Outcome.EXPIRED, SmsChallenge.verify(notes, code, 5, 1121));
        assertFalse(SmsChallenge.hasCode(notes));
        assertEquals(0, SmsChallenge.resendIn(notes, 60, 1121));
    }

    @Test
    void codes_are_random_and_numeric() {
        Map<String, String> a = new HashMap<>();
        Map<String, String> b = new HashMap<>();
        int same = 0;
        for (int i = 0; i < 20; i++) {
            String x = SmsChallenge.issue(a, "+989121234567", "u1", 8, 120, 1000);
            String y = SmsChallenge.issue(b, "+989121234567", "u1", 8, 120, 1000);
            assertTrue(x.chars().allMatch(Character::isDigit));
            if (x.equals(y)) same++;
        }
        assertTrue(same < 2);
        assertNotEquals(a.get(SmsChallenge.SALT), b.get(SmsChallenge.SALT));
    }

    @Test
    void the_gateway_signature_matches_the_shared_test_vector() {
        // The same vector is checked by the gateway's tests (Identity.Gateway.Tests, SmsLoginHookTests).
        assertEquals("a764da6b09824f54bf53c4399cad9254858dc943c31807e4ac139eb38ebc5c24",
                GatewaySmsSender.sign("0123456789abcdef0123456789abcdef", "1700000000", "{\"realm\":\"company\"}"));
    }

    @Test
    void the_sender_needs_a_url_and_a_long_secret() {
        assertFalse(new GatewaySmsSender("", "0123456789abcdef0123456789abcdef").configured());
        assertFalse(new GatewaySmsSender("http://gateway", "short").configured());
        assertTrue(new GatewaySmsSender("http://gateway/", "0123456789abcdef0123456789abcdef").configured());
    }
}
