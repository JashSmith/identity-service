using System.Reflection;

namespace Identity.ArchitectureTests;

public class ArchitectureTests
{
    [Fact]
    public void Domain_assembly_has_no_external_framework_reference()
    {
        var names = typeof(Identity.Domain.User).Assembly.GetReferencedAssemblies().Select(x => x.Name).ToArray();
        Assert.DoesNotContain(names, x => x is "Microsoft.EntityFrameworkCore" or "Microsoft.AspNetCore.Http");
    }
}