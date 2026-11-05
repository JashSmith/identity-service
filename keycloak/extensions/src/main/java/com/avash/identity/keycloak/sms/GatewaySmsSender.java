package com.avash.identity.keycloak.sms;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;

/**
 * Sends SMS codes through the Identity Gateway, so every tenant uses the SMS provider chosen in the admin console.
 * The request is signed with HMAC-SHA256 over {@code "<unix seconds>.<body>"} with a secret only Keycloak and the
 * gateway know ({@code AVASH_SMS_HOOK_SECRET}); the gateway refuses unsigned, wrongly signed or stale requests.
 * The code is never logged.
 */
public final class GatewaySmsSender {

    public static final String PATH = "/api/identity/internal/sms-login/send";
    public static final String TIMESTAMP_HEADER = "X-Avash-Timestamp";
    public static final String SIGNATURE_HEADER = "X-Avash-Signature";

    private static final Logger LOG = Logger.getLogger(GatewaySmsSender.class);
    private static volatile GatewaySmsSender instance;

    private final String gatewayUrl;
    private final String secret;
    private final HttpClient http;

    GatewaySmsSender(String gatewayUrl, String secret) {
        this.gatewayUrl = gatewayUrl == null ? "" : gatewayUrl.replaceAll("/+$", "");
        this.secret = secret == null ? "" : secret;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    /** Configured from the environment of the Keycloak server (AVASH_GATEWAY_URL, AVASH_SMS_HOOK_SECRET). */
    public static GatewaySmsSender get() {
        GatewaySmsSender current = instance;
        if (current == null) {
            synchronized (GatewaySmsSender.class) {
                if (instance == null) instance = new GatewaySmsSender(System.getenv("AVASH_GATEWAY_URL"), System.getenv("AVASH_SMS_HOOK_SECRET"));
                current = instance;
            }
        }
        return current;
    }

    public boolean configured() {
        return !gatewayUrl.isEmpty() && secret.length() >= 32;
    }

    /** True when the gateway accepted the message for delivery. Failures are logged without the code. */
    public boolean send(String realm, String clientId, String phoneNumber, String code, int lifetimeSeconds, String purpose) {
        if (!configured()) {
            LOG.errorf("SMS sign-in in realm %s: AVASH_GATEWAY_URL or AVASH_SMS_HOOK_SECRET (32+ characters) is not set", realm);
            return false;
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("realm", realm);
        payload.put("clientId", clientId);
        payload.put("phoneNumber", phoneNumber);
        payload.put("code", code);
        payload.put("lifetimeSeconds", lifetimeSeconds);
        payload.put("purpose", purpose);
        try {
            String body = JsonSerialization.writeValueAsString(payload);
            String timestamp = Long.toString(System.currentTimeMillis() / 1000);
            HttpRequest request = HttpRequest.newBuilder(URI.create(gatewayUrl + PATH))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/json")
                    .header(TIMESTAMP_HEADER, timestamp)
                    .header(SIGNATURE_HEADER, sign(secret, timestamp, body))
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 == 2) return true;
            LOG.warnf("SMS sign-in in realm %s: the gateway refused the message (HTTP %d)", realm, response.statusCode());
            return false;
        } catch (IOException e) {
            LOG.warnf("SMS sign-in in realm %s: the gateway is unreachable: %s", realm, e.getMessage());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** Hex HMAC-SHA256 of {@code "<timestamp>.<body>"}; the gateway computes the same. */
    public static String sign(String secret, String timestamp, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal((timestamp + "." + body).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256 is not available", e);
        }
    }
}
