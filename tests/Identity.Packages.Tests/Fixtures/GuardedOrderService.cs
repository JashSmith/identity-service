using Avash.Identity.Abstractions;

namespace Identity.Packages.Tests.Fixtures;

/// <summary>
/// Test-only consumer: ten actions guarded with <c>[RequirePermission]</c>, so permission discovery and
/// manifest creation can be verified against a known set. It plays the role of a real service's code.
/// </summary>
public static class OrderPermissions
{
    public const string Application = "order-service";

    public const string ViewOrders = "Orders:Order:View";
    public const string CreateOrders = "Orders:Order:Create";
    public const string EditOrders = "Orders:Order:Edit";
    public const string CancelOrders = "Orders:Order:Cancel";
    public const string ViewInvoices = "Orders:Invoice:View";
    public const string IssueInvoices = "Orders:Invoice:Issue";
    public const string ViewShipments = "Orders:Shipment:View";
    public const string ScheduleShipments = "Orders:Shipment:Schedule";
    public const string ApproveRefunds = "Orders:Refund:Approve";
    public const string ExportReports = "Orders:Report:Export";
}

public sealed record OrderDto(string Id, string CustomerUsername, decimal Total, string Status, string Region = "global");

/// <summary>Exactly one permission per public method; the bodies are irrelevant to the tests.</summary>
public sealed class OrderService
{
    [RequirePermission(OrderPermissions.ViewOrders)]
    public void ListOrders() { }

    [RequirePermission(OrderPermissions.CreateOrders)]
    public void CreateOrder() { }

    [RequirePermission(OrderPermissions.EditOrders)]
    public void EditOrder() { }

    [RequirePermission(OrderPermissions.CancelOrders)]
    public void CancelOrder() { }

    [RequirePermission(OrderPermissions.ViewInvoices)]
    public void ListInvoices() { }

    [RequirePermission(OrderPermissions.IssueInvoices)]
    public void IssueInvoice() { }

    [RequirePermission(OrderPermissions.ViewShipments)]
    public void ListShipments() { }

    [RequirePermission(OrderPermissions.ScheduleShipments)]
    public void ScheduleShipment() { }

    [RequirePermission(OrderPermissions.ApproveRefunds)]
    public void ApproveRefund() { }

    [RequirePermission(OrderPermissions.ExportReports)]
    public void ExportReport() { }
}
