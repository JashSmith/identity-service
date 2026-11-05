package com.avash.identity.keycloak.sms;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Passwordless sign-in on Keycloak's login page: the user enters their mobile number, receives a code by SMS and
 * signs in with it. Whether a number is registered is never revealed: an unknown number gets the same "code sent"
 * page (and no SMS). Wrong codes count towards brute-force protection; codes expire and allow a few attempts.
 * Active only when the realm's {@code iam.smslogin.mode} is {@code passwordless} (the gateway also enables the
 * flow branch only then).
 */
public final class SmsLoginAuthenticator implements Authenticator {

    static final String PHONE_TEMPLATE = "avash-sms-phone.ftl";
    static final String CODE_TEMPLATE = "avash-sms-code.ftl";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (SmsLoginSupport.settings(context.getRealm()).mode() != SmsLoginSettings.Mode.PASSWORDLESS) {
            context.attempted();
            return;
        }
        Map<String, String> notes = SmsLoginSupport.readNotes(context.getAuthenticationSession());
        context.challenge(SmsChallenge.hasCode(notes) ? codeForm(context, notes, null) : phoneForm(context, null, null));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        SmsLoginSettings settings = SmsLoginSupport.settings(context.getRealm());
        if (settings.mode() != SmsLoginSettings.Mode.PASSWORDLESS) {
            context.attempted();
            return;
        }
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        Map<String, String> notes = SmsLoginSupport.readNotes(authSession);

        if (form.containsKey("change-number")) {
            SmsLoginSupport.clearNotes(authSession);
            context.challenge(phoneForm(context, null, null));
        } else if (form.containsKey("resend")) {
            String phone = notes.get(SmsChallenge.PHONE);
            if (phone == null || phone.isEmpty()) context.challenge(phoneForm(context, null, null));
            else sendCode(context, settings, notes, phone);
        } else if (form.containsKey("phone")) {
            String phone = PhoneNumbers.normalize(form.getFirst("phone"));
            if (phone == null) {
                context.challenge(phoneForm(context, form.getFirst("phone"), "avashSmsInvalidPhone"));
            } else if (phone.equals(notes.get(SmsChallenge.PHONE)) && SmsChallenge.hasCode(notes)
                    && SmsChallenge.resendIn(notes, settings.resendSeconds(), SmsLoginSupport.now()) > 0) {
                // Sent a moment ago: show the code page again instead of sending another SMS.
                context.challenge(codeForm(context, notes, null));
            } else {
                sendCode(context, settings, notes, phone);
            }
        } else {
            verifyCode(context, settings, notes, form.getFirst("code"));
        }
    }

    private void sendCode(AuthenticationFlowContext context, SmsLoginSettings settings, Map<String, String> notes, String phone) {
        long now = SmsLoginSupport.now();
        long wait = phone.equals(notes.get(SmsChallenge.PHONE)) ? SmsChallenge.resendIn(notes, settings.resendSeconds(), now) : 0;
        if (wait > 0) {
            context.challenge(codeForm(context, notes, "avashSmsWait"));
            return;
        }
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = SmsLoginSupport.findUser(session, realm, phone);
        String code = SmsChallenge.issue(notes, phone, user == null ? null : user.getId(), settings.codeLength(),
                settings.codeLifetimeSeconds(), now);
        if (user != null && !GatewaySmsSender.get().send(realm.getName(), SmsLoginSupport.clientId(context), phone, code,
                settings.codeLifetimeSeconds(), SmsLoginSupport.PURPOSE_LOGIN)) {
            SmsLoginSupport.clearNotes(context.getAuthenticationSession());
            context.challenge(phoneForm(context, phone, "avashSmsSendFailed"));
            return;
        }
        if (user == null) context.getEvent().detail("phone_number", PhoneNumbers.mask(phone)).error(Errors.USER_NOT_FOUND);
        SmsLoginSupport.writeNotes(context.getAuthenticationSession(), notes);
        context.challenge(codeForm(context, notes, null));
    }

    private void verifyCode(AuthenticationFlowContext context, SmsLoginSettings settings, Map<String, String> notes, String code) {
        String userId = notes.get(SmsChallenge.USER);
        SmsChallenge.Outcome outcome = SmsChallenge.verify(notes, code, settings.maxAttempts(), SmsLoginSupport.now());
        SmsLoginSupport.writeNotes(context.getAuthenticationSession(), notes);
        UserModel user = userId == null || userId.isEmpty() ? null : context.getSession().users().getUserById(context.getRealm(), userId);

        switch (outcome) {
            case VALID -> {
                if (SmsLoginSupport.usable(context.getSession(), context.getRealm(), user)) {
                    SmsLoginSupport.clearNotes(context.getAuthenticationSession());
                    context.setUser(user);
                    context.success();
                    return;
                }
                // Disabled or locked since the code was sent.
                context.getEvent().user(user).error(Errors.USER_DISABLED);
                context.challenge(phoneForm(context, null, "avashSmsWrongCode"));
            }
            case WRONG -> {
                // The user is NOT attached to the sign-in: Keycloak would then show their username on the page and
                // tell whoever typed the number whose account it is. The failure still counts for brute force.
                if (user != null) {
                    context.getEvent().user(user);
                    SmsLoginSupport.countFailure(context, user);
                }
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                context.challenge(codeForm(context, notes, "avashSmsWrongCode"));
            }
            case EXPIRED -> context.challenge(codeForm(context, notes, "avashSmsCodeExpired"));
            case TOO_MANY_ATTEMPTS -> {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                context.challenge(codeForm(context, notes, "avashSmsTooManyAttempts"));
            }
            case NO_CODE -> context.challenge(phoneForm(context, null, null));
        }
    }

    static Response phoneForm(AuthenticationFlowContext context, String typed, String error) {
        LoginFormsProvider form = context.form().setAttribute("smsPhoneInput", typed == null ? "" : typed);
        if (error != null) form.setError(error);
        return form.createForm(PHONE_TEMPLATE);
    }

    static Response codeForm(AuthenticationFlowContext context, Map<String, String> notes, String error) {
        SmsLoginSettings settings = SmsLoginSupport.settings(context.getRealm());
        long now = SmsLoginSupport.now();
        LoginFormsProvider form = context.form()
                .setAttribute("smsPhone", PhoneNumbers.mask(notes.get(SmsChallenge.PHONE)))
                .setAttribute("smsCodeLength", settings.codeLength())
                .setAttribute("smsResendIn", SmsChallenge.resendIn(notes, settings.resendSeconds(), now))
                .setAttribute("smsHasCode", SmsChallenge.hasCode(notes))
                .setAttribute("smsPasswordless", Boolean.TRUE);
        if (error != null) form.setError(error, settings.resendSeconds());
        return form.createForm(CODE_TEMPLATE);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // The number is managed by administrators (gateway); nothing for the user to set up.
    }

    @Override
    public void close() {
        // Stateless.
    }
}
