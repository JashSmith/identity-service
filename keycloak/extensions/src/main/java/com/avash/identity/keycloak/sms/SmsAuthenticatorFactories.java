package com.avash.identity.keycloak.sms;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factories of the SMS authenticators. The Identity Gateway adds them to each tenant's flows and enables the ones
 * the tenant's SMS sign-in mode needs. On the "try another way" page Keycloak shows the messages
 * {@code <id>-display-name} and {@code <id>-help-text} (theme-resources/messages).
 */
public final class SmsAuthenticatorFactories {

    private SmsAuthenticatorFactories() {
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    abstract static class Base implements AuthenticatorFactory {
        private final String id;
        private final String displayType;
        private final String helpText;
        private final Authenticator instance;

        Base(String id, String displayType, String helpText, Authenticator instance) {
            this.id = id;
            this.displayType = displayType;
            this.helpText = helpText;
            this.instance = instance;
        }

        @Override
        public String getId() {
            return id;
        }

        @Override
        public String getDisplayType() {
            return displayType;
        }

        @Override
        public String getHelpText() {
            return helpText;
        }

        @Override
        public String getReferenceCategory() {
            return "sms";
        }

        @Override
        public boolean isConfigurable() {
            return false;
        }

        @Override
        public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
            return REQUIREMENTS;
        }

        @Override
        public boolean isUserSetupAllowed() {
            return false;
        }

        @Override
        public List<ProviderConfigProperty> getConfigProperties() {
            return List.of();
        }

        @Override
        public Authenticator create(KeycloakSession session) {
            return instance;
        }

        @Override
        public void init(Config.Scope config) {
            // Settings come from realm attributes (iam.smslogin.*) and the environment (gateway URL, secret).
        }

        @Override
        public void postInit(KeycloakSessionFactory factory) {
            // Nothing to prepare.
        }

        @Override
        public void close() {
            // Stateless.
        }
    }

    /** Passwordless sign-in on the login page. */
    public static final class Login extends Base {
        public static final String ID = "avash-sms-login";

        public Login() {
            super(ID, "Avash SMS sign-in", "Sign in with a code sent by SMS to the user's mobile number (no password).",
                    new SmsLoginAuthenticator());
        }
    }

    /** Second factor on the login page. */
    public static final class Otp extends Base {
        public static final String ID = "avash-sms-otp";

        public Otp() {
            super(ID, "Avash SMS code (second factor)", "After the password, a code is sent by SMS to the user's mobile number.",
                    new SmsOtpAuthenticator());
        }
    }

    /** Passwordless sign-in at the token endpoint (phone_number + sms_code). */
    public static final class DirectLogin extends Base {
        public static final String ID = "avash-sms-login-direct";

        public DirectLogin() {
            super(ID, "Avash SMS sign-in (direct grant)", "phone_number, then phone_number + sms_code at the token endpoint.",
                    new DirectGrantSmsAuthenticator(false));
        }
    }

    /** Second factor at the token endpoint (username + password + sms_code). */
    public static final class DirectOtp extends Base {
        public static final String ID = "avash-sms-otp-direct";

        public DirectOtp() {
            super(ID, "Avash SMS code (direct grant, second factor)", "After the password, sms_code at the token endpoint.",
                    new DirectGrantSmsAuthenticator(true));
        }
    }
}
