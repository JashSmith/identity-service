using Identity.Application;
using Identity.Application.Schedules;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

/// <summary>
/// Weekly access schedules on the realm (default), business roles, permissions and users
/// (precedence user &gt; permission &gt; role &gt; realm). DELETE makes the entity inherit again.
/// </summary>
public static class ScheduleEndpoints
{
    public static IEndpointRouteBuilder MapSchedules(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/schedules").WithTags("Schedules");

        MapTarget(g, "/realm", ScheduleTarget.Realm, "Realm");
        MapTarget(g, "/roles/{id}", ScheduleTarget.Role, "Role");
        MapTarget(g, "/permissions/{id}", ScheduleTarget.Permission, "Permission");
        MapTarget(g, "/users/{id}", ScheduleTarget.User, "User", manageableUser: true);

        g.MapGet("/users/{id}/effective", async (string id, AccessScheduleService schedules, CancellationToken ct) =>
                (await schedules.GetSnapshotAsync(id, ct)).ToHttpResult(snapshot => Results.Ok(snapshot)))
            .RequireAuthorization(IamPermissions.SchedulesRead)
            .ForManageableUser()
            .WithName("GetEffectiveUserSchedule")
            .Produces<AccessScheduleSnapshot>(200).ProducesProblem(404);

        // The caller's own resolved schedules; consumer services evaluate them per permission.
        app.MapGet("/api/identity/access-schedule", async (ICurrentUserContext current, AccessScheduleService schedules, CancellationToken ct) =>
                current.UserId is null
                    ? Results.Unauthorized()
                    : (await schedules.GetSnapshotAsync(current.UserId, ct)).ToHttpResult(snapshot => Results.Ok(snapshot)))
            .WithTags("Access")
            .RequireAuthorization()
            .WithName("GetAccessSchedule")
            .Produces<AccessScheduleSnapshot>(200);

        return app;
    }

    private static void MapTarget(RouteGroupBuilder g, string pattern, ScheduleTarget target, string name, bool manageableUser = false)
    {
        var targetName = target.ToString().ToLowerInvariant();

        var get = g.MapGet(pattern, async (HttpContext http, AccessScheduleService schedules, CancellationToken ct) =>
            {
                var id = Id(http);
                return (await schedules.GetAsync(target, id, ct)).ToHttpResult(schedule =>
                    Results.Ok(new ScheduleSettingDto(targetName, id, schedule?.ToString(), schedule?.ToDto())));
            })
            .RequireAuthorization(IamPermissions.SchedulesRead)
            .WithName($"Get{name}Schedule")
            .Produces<ScheduleSettingDto>(200).ProducesProblem(404);

        var put = g.MapPut(pattern, async (HttpContext http, WeeklyScheduleDto body, AccessScheduleService schedules, CancellationToken ct) =>
            {
                if (!WeeklySchedule.TryCreate(body.Unrestricted, body.Days, out var schedule, out var error))
                    return Error.Validation("schedule.invalid", error!).ToProblem();
                var id = Id(http);
                return (await schedules.SetAsync(target, id, schedule, ct)).ToHttpResult(() =>
                    Results.Ok(new ScheduleSettingDto(targetName, id, schedule.ToString(), schedule.ToDto())));
            })
            .RequireAuthorization(IamPermissions.SchedulesManage)
            .WithName($"Set{name}Schedule")
            .Produces<ScheduleSettingDto>(200).ProducesProblem(400).ProducesProblem(404);

        var delete = g.MapDelete(pattern, async (HttpContext http, AccessScheduleService schedules, CancellationToken ct) =>
                (await schedules.SetAsync(target, Id(http), null, ct)).ToHttpResult(() => Results.NoContent()))
            .RequireAuthorization(IamPermissions.SchedulesManage)
            .WithName($"Clear{name}Schedule")
            .Produces(204).ProducesProblem(404);

        if (!manageableUser) return;
        get.ForManageableUser();
        put.ForManageableUser();
        delete.ForManageableUser();
    }

    private static string? Id(HttpContext http) => http.GetRouteValue("id") as string;
}
