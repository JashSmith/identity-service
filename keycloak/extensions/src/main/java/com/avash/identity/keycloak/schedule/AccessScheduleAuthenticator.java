package com.avash.identity.keycloak.schedule;

import jakarta.ws.rs.core.Response;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Refuses sign-in on Keycloak's own login pages (SSO) outside the user's weekly schedule, with the same rules as
 * the Identity Gateway's login: the user's {@code access.schedule} overrides everything; otherwise the user may sign
 * in whenever one of their business roles (groups) allows it, a role without a schedule following the realm's
 * default; without roles the realm default applies; no schedule anywhere means unrestricted.
 * Must run after the user is identified (after the username/password form).
 */
public final class AccessScheduleAuthenticator implements Authenticator {

    static final String TIME_ZONE = "timeZone";
    static final String DEFAULT_TIME_ZONE = "Asia/Tehran";
    static final String MESSAGE = "accessOutsideSchedule";

    /** Configuration groups of the gateway; they are not business roles. */
    private static final Set<String> RESERVED_GROUPS = Set.of("super-admins", "iam-scope-registry");

    private static final Logger LOG = Logger.getLogger(AccessScheduleAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            // Placed before the user is known: nothing to check yet.
            context.attempted();
            return;
        }

        boolean allowed;
        try {
            WeeklySchedule schedule = resolve(context.getRealm(), user);
            allowed = schedule.allows(ZonedDateTime.now(timeZone(context.getAuthenticatorConfig())));
        } catch (IllegalArgumentException e) {
            // A broken stored schedule must not grant access: deny and say why in the log.
            LOG.errorf("Invalid %s for user %s in realm %s: %s", WeeklySchedule.ATTRIBUTE, user.getId(),
                    context.getRealm().getName(), e.getMessage());
            allowed = false;
        }

        if (allowed) {
            context.success();
            return;
        }
        context.getEvent().user(user).error(Errors.ACCESS_DENIED);
        Response page = context.form().setError(MESSAGE).createErrorPage(Response.Status.FORBIDDEN);
        context.failure(AuthenticationFlowError.ACCESS_DENIED, page);
    }

    static WeeklySchedule resolve(RealmModel realm, UserModel user) {
        WeeklySchedule own = WeeklySchedule.parse(user.getFirstAttribute(WeeklySchedule.ATTRIBUTE));
        if (own != null) return own;

        WeeklySchedule realmDefault = WeeklySchedule.parse(realm.getAttribute(WeeklySchedule.ATTRIBUTE));
        WeeklySchedule fallback = realmDefault != null ? realmDefault : WeeklySchedule.UNRESTRICTED;

        List<GroupModel> roles = user.getGroupsStream().filter(g -> !RESERVED_GROUPS.contains(g.getName())).toList();
        if (roles.isEmpty()) return fallback;

        WeeklySchedule result = null;
        for (GroupModel role : roles) {
            WeeklySchedule schedule = WeeklySchedule.parse(role.getFirstAttribute(WeeklySchedule.ATTRIBUTE));
            WeeklySchedule effective = schedule != null ? schedule : fallback;
            result = result == null ? effective : result.union(effective);
        }
        return result;
    }

    private static ZoneId timeZone(AuthenticatorConfigModel config) {
        Map<String, String> values = config == null ? null : config.getConfig();
        String zone = values == null ? null : values.get(TIME_ZONE);
        return ZoneId.of(zone == null || zone.isBlank() ? DEFAULT_TIME_ZONE : zone);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No form of its own.
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
        // Nothing for the user to set up.
    }

    @Override
    public void close() {
        // Stateless.
    }
}
