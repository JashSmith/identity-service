package com.avash.identity.keycloak.schedule;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/** Registers {@link AccessScheduleAuthenticator}; the Identity Gateway adds it to each tenant's browser flow. */
public final class AccessScheduleAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "avash-access-schedule";

    private static final AccessScheduleAuthenticator INSTANCE = new AccessScheduleAuthenticator();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    private static final List<ProviderConfigProperty> CONFIG = ProviderConfigurationBuilder.create()
            .property()
            .name(AccessScheduleAuthenticator.TIME_ZONE)
            .label("Time zone")
            .helpText("IANA time zone the schedules are written in (the gateway's Identity:Schedules:TimeZone).")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(AccessScheduleAuthenticator.DEFAULT_TIME_ZONE)
            .add()
            .build();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Avash weekly access schedule";
    }

    @Override
    public String getHelpText() {
        return "Refuses sign-in outside the user's weekly access schedule (access.schedule attributes).";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
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
        return CONFIG;
    }

    @Override
    public Authenticator create(org.keycloak.models.KeycloakSession session) {
        return INSTANCE;
    }

    @Override
    public void init(Config.Scope config) {
        // No server-wide configuration.
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
