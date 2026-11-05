package com.avash.identity.keycloak.sms;

import jakarta.ws.rs.core.MultivaluedMap;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;

/**
 * SMS codes at the token endpoint (direct grant, used by the gateway's login API for applications with their own
 * sign-in form). Two calls: without {@code sms_code} a code is sent and the answer is HTTP 401 with
 * {@code error = sms_code_sent} (passwordless) or {@code sms_code_required} (second factor), {@code expires_in} and
 * {@code resend_in}; the second call repeats the request with {@code sms_code}. The code state lives in Keycloak's
 * single-use object store (cluster-wide, expiring), keyed by realm, client and number (passwordless) or user
 * (second factor). Unknown numbers get the same answer as known ones and no SMS.
 */
public final class DirectGrantSmsAuthenticator implements Authenticator {

    private final boolean secondFactor;

    DirectGrantSmsAuthenticator(boolean secondFactor) {
        this.secondFactor = secondFactor;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        SmsLoginSettings settings = SmsLoginSupport.settings(context.getRealm());
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        if (secondFactor) authenticateSecondFactor(context, settings, params);
        else authenticatePasswordless(context, settings, params);
    }

    private void authenticatePasswordless(AuthenticationFlowContext context, SmsLoginSettings settings, MultivaluedMap<String, String> params) {
        String typed = params.getFirst("phone_number");
        if (typed == null || typed.isBlank()) {
            // A username/password request: the password branch handles it.
            context.attempted();
            return;
        }
        if (settings.mode() != SmsLoginSettings.Mode.PASSWORDLESS) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    SmsLoginSupport.json(400, "invalid_request", "SMS sign-in is not enabled for this organisation.", null));
            return;
        }
        String phone = PhoneNumbers.normalize(typed);
        if (phone == null) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    SmsLoginSupport.json(400, "invalid_request", "phone_number is not an Iranian mobile number.", null));
            return;
        }
        String key = "avash-sms:" + context.getRealm().getId() + ":" + SmsLoginSupport.clientId(context) + ":" + phone;
        String code = params.getFirst("sms_code");
        if (code == null || code.isBlank()) {
            UserModel user = SmsLoginSupport.findUser(context.getSession(), context.getRealm(), phone);
            send(context, settings, key, phone, user, "sms_code_sent", SmsLoginSupport.PURPOSE_LOGIN);
            return;
        }
        verify(context, settings, key, code, null);
    }

    private void authenticateSecondFactor(AuthenticationFlowContext context, SmsLoginSettings settings, MultivaluedMap<String, String> params) {
        if (settings.mode() != SmsLoginSettings.Mode.SECOND_FACTOR) {
            context.success();
            return;
        }
        UserModel user = context.getUser();
        String phone = SmsLoginSupport.phoneOf(user);
        if (phone == null) {
            context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.ACCESS_DENIED, SmsLoginSupport.json(401, "invalid_grant",
                    "No mobile number is registered for this user; an administrator must add one.", Map.of("sms_error", "no_phone_number")));
            return;
        }
        String key = "avash-sms2:" + context.getRealm().getId() + ":" + SmsLoginSupport.clientId(context) + ":" + user.getId();
        String code = params.getFirst("sms_code");
        if (code == null || code.isBlank()) {
            send(context, settings, key, phone, user, "sms_code_required", SmsLoginSupport.PURPOSE_SECOND_FACTOR);
            return;
        }
        verify(context, settings, key, code, user);
    }

    private void send(AuthenticationFlowContext context, SmsLoginSettings settings, String key, String phone, UserModel user,
                      String error, String purpose) {
        SingleUseObjectProvider store = context.getSession().singleUseObjects();
        Map<String, String> notes = SmsChallenge.copy(store.get(key));
        long now = SmsLoginSupport.now();
        long wait = SmsChallenge.resendIn(notes, settings.resendSeconds(), now);
        if (wait > 0 && SmsChallenge.hasCode(notes)) {
            // A code was sent a moment ago: answer the same without sending another one.
            context.challenge(codeSent(error, SmsChallenge.expiresIn(notes, now), wait));
            return;
        }
        String code = SmsChallenge.issue(notes, phone, user == null ? null : user.getId(), settings.codeLength(),
                settings.codeLifetimeSeconds(), now);
        if (user != null && !GatewaySmsSender.get().send(context.getRealm().getName(), SmsLoginSupport.clientId(context), phone,
                code, settings.codeLifetimeSeconds(), purpose)) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                    SmsLoginSupport.json(503, "temporarily_unavailable", "The SMS could not be sent; try again later.", null));
            return;
        }
        if (user == null) context.getEvent().detail("phone_number", PhoneNumbers.mask(phone)).error(Errors.USER_NOT_FOUND);
        store.put(key, Math.max(settings.codeLifetimeSeconds(), settings.resendSeconds()), notes);
        context.challenge(codeSent(error, settings.codeLifetimeSeconds(), settings.resendSeconds()));
    }

    private void verify(AuthenticationFlowContext context, SmsLoginSettings settings, String key, String code, UserModel knownUser) {
        SingleUseObjectProvider store = context.getSession().singleUseObjects();
        Map<String, String> stored = store.get(key);
        Map<String, String> notes = SmsChallenge.copy(stored);
        String userId = notes.get(SmsChallenge.USER);
        SmsChallenge.Outcome outcome = SmsChallenge.verify(notes, code, settings.maxAttempts(), SmsLoginSupport.now());
        if (stored != null) store.replace(key, notes);

        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = knownUser != null ? knownUser
                : userId == null || userId.isEmpty() ? null : session.users().getUserById(realm, userId);
        if (outcome == SmsChallenge.Outcome.VALID && SmsLoginSupport.usable(session, realm, user)) {
            if (knownUser == null) context.setUser(user);
            context.success();
            return;
        }
        if (user != null && knownUser == null) context.setUser(user);
        if (user != null) context.getEvent().user(user);
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
        String description = switch (outcome) {
            case EXPIRED -> "The SMS code has expired; request a new one.";
            case TOO_MANY_ATTEMPTS -> "Too many wrong SMS codes; request a new one.";
            case NO_CODE -> "No SMS code was requested, or it has expired.";
            default -> "Invalid SMS code.";
        };
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, SmsLoginSupport.json(401, "invalid_grant", description,
                Map.of("sms_error", outcome.name().toLowerCase())));
    }

    private static jakarta.ws.rs.core.Response codeSent(String error, long expiresIn, long resendIn) {
        Map<String, Object> extra = new HashMap<>();
        extra.put("expires_in", expiresIn);
        extra.put("resend_in", resendIn);
        return SmsLoginSupport.json(401, error, "An SMS code was sent; repeat the request with sms_code.", extra);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // The token endpoint has no form actions.
    }

    @Override
    public boolean requiresUser() {
        return secondFactor;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Nothing for the user to set up.
    }

    @Override
    public void close() {
        // Stateless.
    }
}
