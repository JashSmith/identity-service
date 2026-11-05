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

/**
 * Second factor on Keycloak's login page: after the password (and the weekly schedule), a code is sent to the
 * user's registered mobile number. A user without a number cannot finish signing in and is told to contact an
 * administrator. Active only when the realm's {@code iam.smslogin.mode} is {@code second-factor}.
 */
public final class SmsOtpAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        SmsLoginSettings settings = SmsLoginSupport.settings(context.getRealm());
        if (settings.mode() != SmsLoginSettings.Mode.SECOND_FACTOR) {
            context.success();
            return;
        }
        UserModel user = context.getUser();
        String phone = SmsLoginSupport.phoneOf(user);
        if (phone == null) {
            context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
            Response page = context.form().setError("avashSmsNoPhone").createErrorPage(Response.Status.FORBIDDEN);
            context.failure(AuthenticationFlowError.ACCESS_DENIED, page);
            return;
        }
        Map<String, String> notes = SmsLoginSupport.readNotes(context.getAuthenticationSession());
        boolean current = user.getId().equals(notes.get(SmsChallenge.USER)) && SmsChallenge.expiresIn(notes, SmsLoginSupport.now()) > 0;
        if (current) context.challenge(codeForm(context, notes, null));
        else sendCode(context, settings, notes, user, phone);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        SmsLoginSettings settings = SmsLoginSupport.settings(context.getRealm());
        UserModel user = context.getUser();
        String phone = SmsLoginSupport.phoneOf(user);
        if (settings.mode() != SmsLoginSettings.Mode.SECOND_FACTOR || phone == null) {
            authenticate(context);
            return;
        }
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        Map<String, String> notes = SmsLoginSupport.readNotes(context.getAuthenticationSession());
        if (form.containsKey("resend")) {
            sendCode(context, settings, notes, user, phone);
            return;
        }

        SmsChallenge.Outcome outcome = SmsChallenge.verify(notes, form.getFirst("code"), settings.maxAttempts(), SmsLoginSupport.now());
        SmsLoginSupport.writeNotes(context.getAuthenticationSession(), notes);
        switch (outcome) {
            case VALID -> {
                SmsLoginSupport.clearNotes(context.getAuthenticationSession());
                context.success();
            }
            case WRONG -> {
                context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, codeForm(context, notes, "avashSmsWrongCode"));
            }
            case EXPIRED -> context.challenge(codeForm(context, notes, "avashSmsCodeExpired"));
            case TOO_MANY_ATTEMPTS -> {
                context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, codeForm(context, notes, "avashSmsTooManyAttempts"));
            }
            case NO_CODE -> sendCode(context, settings, notes, user, phone);
        }
    }

    private void sendCode(AuthenticationFlowContext context, SmsLoginSettings settings, Map<String, String> notes, UserModel user, String phone) {
        long now = SmsLoginSupport.now();
        if (user.getId().equals(notes.get(SmsChallenge.USER)) && SmsChallenge.resendIn(notes, settings.resendSeconds(), now) > 0) {
            context.challenge(codeForm(context, notes, SmsChallenge.hasCode(notes) ? "avashSmsWait" : "avashSmsTooManyAttempts"));
            return;
        }
        String code = SmsChallenge.issue(notes, phone, user.getId(), settings.codeLength(), settings.codeLifetimeSeconds(), now);
        if (!GatewaySmsSender.get().send(context.getRealm().getName(), SmsLoginSupport.clientId(context), phone, code,
                settings.codeLifetimeSeconds(), SmsLoginSupport.PURPOSE_SECOND_FACTOR)) {
            SmsLoginSupport.clearNotes(context.getAuthenticationSession());
            Response page = context.form().setError("avashSmsSendFailed").createErrorPage(Response.Status.SERVICE_UNAVAILABLE);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, page);
            return;
        }
        SmsLoginSupport.writeNotes(context.getAuthenticationSession(), notes);
        context.challenge(codeForm(context, notes, null));
    }

    private static Response codeForm(AuthenticationFlowContext context, Map<String, String> notes, String error) {
        SmsLoginSettings settings = SmsLoginSupport.settings(context.getRealm());
        LoginFormsProvider form = context.form()
                .setAttribute("smsPhone", PhoneNumbers.mask(notes.get(SmsChallenge.PHONE)))
                .setAttribute("smsCodeLength", settings.codeLength())
                .setAttribute("smsResendIn", SmsChallenge.resendIn(notes, settings.resendSeconds(), SmsLoginSupport.now()))
                .setAttribute("smsHasCode", SmsChallenge.hasCode(notes))
                .setAttribute("smsPasswordless", Boolean.FALSE);
        if (error != null) form.setError(error, settings.resendSeconds());
        return form.createForm(SmsLoginAuthenticator.CODE_TEMPLATE);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // The number is managed by administrators (gateway).
    }

    @Override
    public void close() {
        // Stateless.
    }
}
