using Company.Identity.Abstractions;

namespace SampleApp;

/// <summary>
/// Sample consumer service demonstrating the permission-registration flow:
/// every action is annotated with <c>[RequirePermission]</c>; on startup the service
/// discovers those permissions and pushes a manifest to the Identity Facade, which
/// mirrors them into Keycloak realm roles so they appear in token claims.
/// Exactly ten distinct permissions are declared — see <c>Identity.Sample.Tests</c>.
/// </summary>
public static class OrderPermissions
{
    public const string ViewOrders = "Orders.View";
    public const string CreateOrders = "Orders.Create";
    public const string EditOrders = "Orders.Edit";
    public const string CancelOrders = "Orders.Cancel";
    public const string ViewInvoices = "Orders.Invoices.View";
    public const string IssueInvoices = "Orders.Invoices.Issue";
    public const string ViewShipments = "Orders.Shipments.View";
    public const string ScheduleShipments = "Orders.Shipments.Schedule";
    public const string ApproveRefunds = "Orders.Refunds.Approve";
    public const string ExportReports = "Orders.Reports.Export";
}

public sealed record OrderDto(string Id, string CustomerUsername, decimal Total, string Status);

public sealed record InvoiceDto(string Id, string OrderId, decimal Amount, bool Issued);

public sealed record ShipmentDto(string Id, string OrderId, DateTimeOffset? ScheduledAt, string Carrier);

public sealed record RefundDto(string Id, string OrderId, decimal Amount, bool Approved);

/// <summary>Ten permission-guarded actions — one per declared permission.</summary>
public sealed class OrderService
{
    private static readonly OrderDto[] s_orders =
    [
        new("ord-1", "admin", 120.50m, "open"),
        new("ord-2", "alice", 49.99m, "shipped"),
        new("ord-3", "bob", 310.00m, "cancelled"),
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

    private static OrderDto Find(string orderId) =>
        s_orders.FirstOrDefault(o => o.Id == orderId) ??
        throw new KeyNotFoundException($"Order '{orderId}' not found.");
}
