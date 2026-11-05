package com.avash.identity.keycloak.sms;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;

/** Helpers shared by the SMS authenticators. */
final class SmsLoginSupport {

    static final String PURPOSE_LOGIN = "login";
    static final String PURPOSE_SECOND_FACTOR = "second-factor";

    private SmsLoginSupport() {
    }

    static SmsLoginSettings settings(RealmModel realm) {
        return SmsLoginSettings.from(realm::getAttribute);
    }

    static long now() {
        return System.currentTimeMillis() / 1000;
    }

    /** The code state of this browser sign-in (authentication-session notes). */
    static Map<String, String> readNotes(AuthenticationSessionModel session) {
        Map<String, String> notes = SmsChallenge.copy(null);
        for (String key : SmsChallenge.KEYS) {
            String value = session.getAuthNote(key);
            if (value != null) notes.put(key, value);
        }
        return notes;
    }

    static void writeNotes(AuthenticationSessionModel session, Map<String, String> notes) {
        for (String key : SmsChallenge.KEYS) {
            String value = notes.get(key);
            if (value == null) session.removeAuthNote(key);
            else session.setAuthNote(key, value);
        }
    }

    static void clearNotes(AuthenticationSessionModel session) {
        for (String key : SmsChallenge.KEYS) session.removeAuthNote(key);
    }

    /** The one enabled user with this number; null when none, several (ambiguous) or disabled. */
    static UserModel findUser(KeycloakSession session, RealmModel realm, String phone) {
        List<UserModel> users = session.users().searchForUserByUserAttributeStream(realm, PhoneNumbers.ATTRIBUTE, phone)
                .limit(2).toList();
        if (users.size() != 1) return null;
        UserModel user = users.get(0);
        return usable(session, realm, user) ? user : null;
    }

    /** Enabled and not locked by brute-force protection. */
    static boolean usable(KeycloakSession session, RealmModel realm, UserModel user) {
        if (user == null || !user.isEnabled()) return false;
        if (!realm.isBruteForceProtected()) return true;
        BruteForceProtector protector = session.getProvider(BruteForceProtector.class);
        return protector == null || !protector.isTemporarilyDisabled(session, realm, user);
    }

    /** Records a failed sign-in of {@code user} for brute-force protection without attaching the user to the flow. */
    static void countFailure(AuthenticationFlowContext context, UserModel user) {
        RealmModel realm = context.getRealm();
        if (!realm.isBruteForceProtected()) return;
        BruteForceProtector protector = context.getSession().getProvider(BruteForceProtector.class);
        if (protector != null) protector.failedLogin(realm, user, context.getConnection(), context.getUriInfo());
    }

    static String phoneOf(UserModel user) {
        return PhoneNumbers.normalize(user.getFirstAttribute(PhoneNumbers.ATTRIBUTE));
    }

    static String clientId(AuthenticationFlowContext context) {
        return context.getAuthenticationSession().getClient().getClientId();
    }

    /** An OAuth-style JSON answer from the token endpoint (direct grant). */
    static Response json(int status, String error, String description, Map<String, Object> extra) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        if (extra != null) body.putAll(extra);
        return Response.status(status).entity(body).type(MediaType.APPLICATION_JSON_TYPE).build();
    }
}
