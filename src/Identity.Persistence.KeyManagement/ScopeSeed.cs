#pragma warning disable CS0618
using Microsoft.EntityFrameworkCore;

namespace Identity.Persistence.KeyManagement;

public static class ScopeSeed
{
    public static async Task EnsureSeededAsync(KeyMetadataDbContext db, CancellationToken ct)
    {
        await db.Database.EnsureCreatedAsync(ct);

        async Task<ScopeDefinitionEntity> EnsureScope(string key, string display, string? desc)
        {
            var e = await db.ScopeDefinitions.FirstOrDefaultAsync(x => x.Key == key, ct);
            if (e is not null) return e;
            e = new ScopeDefinitionEntity { Id = Guid.NewGuid(), Key = key, DisplayName = display, Description = desc, IsActive = true, ValueType = "String", CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow };
            db.ScopeDefinitions.Add(e);
            return e;
        }

        async Task<ApplicationResourceEntity> EnsureResource(string key, string display)
        {
            var e = await db.ApplicationResources.FirstOrDefaultAsync(x => x.Key == key, ct);
            if (e is not null) return e;
            e = new ApplicationResourceEntity { Id = Guid.NewGuid(), Key = key, DisplayName = display };
            db.ApplicationResources.Add(e);
            return e;
        }

        var region = await EnsureScope("region", "Region", "Geographic region");
        var branch = await EnsureScope("branch", "Branch", "Branch identifier");
        var department = await EnsureScope("department", "Department", null);
        var organization = await EnsureScope("organization", "Organization", null);
        var warehouse = await EnsureScope("warehouse", "Warehouse", null);
        var customer = await EnsureScope("customer", "Customer", null);
        var project = await EnsureScope("project", "Project", null);
        var testKey = await EnsureScope("test-key", "Test Key", "Test scope for integration tests");

        var orders = await EnsureResource("Orders", "Orders");
        var branches = await EnsureResource("Branches", "Branches");
        var employees = await EnsureResource("Employees", "Employees");
        var projectTasks = await EnsureResource("ProjectTasks", "Project Tasks");
        var projectDocs = await EnsureResource("ProjectDocuments", "Project Documents");
        var customerOrders = await EnsureResource("CustomerOrders", "Customer Orders");
        var resourceA = await EnsureResource("ResourceA", "Test Resource A");

        await db.SaveChangesAsync(ct);

        async Task Map(ScopeDefinitionEntity s, ApplicationResourceEntity r)
        {
            var exists = await db.ScopeResourceMappings.AnyAsync(x => x.ScopeDefinitionId == s.Id && x.ApplicationResourceId == r.Id, ct);
            if (!exists) db.ScopeResourceMappings.Add(new ScopeResourceMappingEntity { ScopeDefinitionId = s.Id, ApplicationResourceId = r.Id });
        }

        await Map(region, orders); await Map(region, branches); await Map(region, employees);
        await Map(branch, orders); await Map(branch, employees);
        await Map(project, projectTasks); await Map(project, projectDocs);
        await Map(testKey, resourceA);
        await Map(warehouse, orders);
        await Map(customer, customerOrders);
        await Map(customer, orders);
        await Map(department, employees);
        await Map(organization, employees);

        await db.SaveChangesAsync(ct);
    }
}
