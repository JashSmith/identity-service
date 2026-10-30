using Identity.Admin.Auth;
using Identity.Admin.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Radzen;

namespace Identity.Admin.Components.Shared;

/// <summary>
/// Base of the console pages: gateway access, permission checks and one place that turns gateway errors into
/// Persian notifications (and an expired session into a new sign-in).
/// </summary>
[Authorize]
public abstract class ConsolePage : ComponentBase
{
    [Inject] protected GatewayApi Api { get; set; } = default!;
    [Inject] protected NotificationService Notifications { get; set; } = default!;
    [Inject] protected DialogService Dialogs { get; set; } = default!;
    [Inject] protected NavigationManager Navigation { get; set; } = default!;
    [CascadingParameter] protected Task<AuthenticationState> AuthenticationState { get; set; } = default!;

    protected bool Busy { get; private set; }

    protected async Task<bool> Can(string permission) => (await AuthenticationState).User.Has(permission);

    /// <summary>Runs a gateway call; on failure shows the error and returns false.</summary>
    protected async Task<bool> RunAsync(Func<Task> action, string? success = null)
    {
        Busy = true;
        try
        {
            await action();
            if (success is not null) Notifications.Notify(NotificationSeverity.Success, success, duration: 3000);
            return true;
        }
        catch (ApiException ex) when (ex.Status == 401)
        {
            Navigation.NavigateTo($"/login?returnUrl={Uri.EscapeDataString("/" + Navigation.ToBaseRelativePath(Navigation.Uri))}", forceLoad: true);
            return false;
        }
        catch (ApiException ex)
        {
            Notifications.Notify(NotificationSeverity.Error, ex.PersianTitle, ex.Details, duration: 8000);
            return false;
        }
        catch (HttpRequestException)
        {
            Notifications.Notify(NotificationSeverity.Error, "ارتباط با درگاه هویت برقرار نشد", duration: 8000);
            return false;
        }
        finally
        {
            Busy = false;
        }
    }

    protected Task<bool> ConfirmAsync(string message) =>
        Dialogs.Confirm(message, "تأیید", new ConfirmOptions { OkButtonText = "بله", CancelButtonText = "انصراف" })
            .ContinueWith(t => t.Result == true);
}
