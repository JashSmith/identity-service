using Avash.Identity.Abstractions;

namespace SampleApp;

/// <summary>
/// Sample consumer service demonstrating the permission-registration flow:
/// every action is annotated with <c>[RequirePermission]</c>; on startup the service
/// discovers those permissions and pushes a manifest to the Identity Gateway, which
/// stores them as client roles of the order-service application, so they appear in tokens as
/// <c>order-service:Module:Resource:Action</c>.
/// Exactly ten distinct permissions are declared — see <c>Identity.Sample.Tests</c>.
/// </summary>
public static class OrderPermissions
{
    public const string Application = "order-service";

    /// <summary>The name as it appears in tokens.</summary>
    public static string Full(string local) => $"{Application}:{local}";

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

public sealed record InvoiceDto(string Id, string OrderId, decimal Amount, bool Issued);

public sealed record ShipmentDto(string Id, string OrderId, DateTimeOffset? ScheduledAt, string Carrier);

public sealed record RefundDto(string Id, string OrderId, decimal Amount, bool Approved);

/// <summary>Ten permission-guarded actions — one per declared permission.</summary>
public sealed class OrderService
{
    private static readonly OrderDto[] s_orders =
    [
        new("ord-1", "admin", 120.50m, "open", "tehran-1"),
        new("ord-2", "alice", 49.99m, "shipped", "tehran-2"),
        new("ord-3", "bob", 310.00m, "cancelled", "global"),
    ];

    [RequirePermission(OrderPermissions.ViewOrders)]
    public IReadOnlyCollection<OrderDto> ListOrders() => s_orders;

    [RequirePermission(OrderPermissions.CreateOrders)]
    public OrderDto CreateOrder(string customerUsername, decimal total)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(customerUsername);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(total);
        return new OrderDto($"ord-{Guid.NewGuid():N}"[..12], customerUsername, total, "open");
    }

    [RequirePermission(OrderPermissions.EditOrders)]
    public OrderDto EditOrder(string orderId, decimal newTotal)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(orderId);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(newTotal);
        var order = Find(orderId);
        return order with { Total = newTotal };
    }

    [RequirePermission(OrderPermissions.CancelOrders)]
    public OrderDto CancelOrder(string orderId)
    {
        var order = Find(orderId);
        return order with { Status = "cancelled" };
    }

    [RequirePermission(OrderPermissions.ViewInvoices)]
    public IReadOnlyCollection<InvoiceDto> ListInvoices(string orderId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(orderId);
        var order = Find(orderId);
        return [new InvoiceDto($"inv-{order.Id}", order.Id, order.Total, order.Status != "open")];
    }

    [RequirePermission(OrderPermissions.IssueInvoices)]
    public InvoiceDto IssueInvoice(string orderId)
    {
        var order = Find(orderId);
        return new InvoiceDto($"inv-{order.Id}", order.Id, order.Total, true);
    }

    [RequirePermission(OrderPermissions.ViewShipments)]
    public IReadOnlyCollection<ShipmentDto> ListShipments(string orderId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(orderId);
        return [new ShipmentDto($"shp-{orderId}", orderId, null, "default-carrier")];
    }

    [RequirePermission(OrderPermissions.ScheduleShipments)]
    public ShipmentDto ScheduleShipment(string orderId, DateTimeOffset shipsAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(orderId);
        return new ShipmentDto($"shp-{orderId}", orderId, shipsAt, "express-carrier");
    }

    [RequirePermission(OrderPermissions.ApproveRefunds)]
    public RefundDto ApproveRefund(string orderId, decimal amount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(orderId);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(amount);
        return new RefundDto($"ref-{orderId}", orderId, amount, true);
    }

    [RequirePermission(OrderPermissions.ExportReports)]
    public string ExportReport(string format)
    {
        var allowed = new[] { "csv", "json" };
        if (!allowed.Contains(format, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException($"Unsupported format '{format}'.", nameof(format));
        return $"report.{format.ToLowerInvariant()}";
    }

    /// <summary>EF-Core-friendly scoped filter — caller does Where(allowed.Contains(x.Region)) in the DB query.</summary>
    public IReadOnlyCollection<OrderDto> ListOrdersFiltered(IReadOnlyCollection<string> allowedRegions)
        => s_orders.Where(o => allowedRegions.Contains(o.Region, StringComparer.Ordinal)).ToArray();

    private static OrderDto Find(string orderId) =>
        s_orders.FirstOrDefault(o => o.Id == orderId) ??
        throw new KeyNotFoundException($"Order '{orderId}' not found.");
}