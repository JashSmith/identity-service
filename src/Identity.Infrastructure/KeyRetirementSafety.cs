using Identity.Application;using Identity.Domain;
namespace Identity.Infrastructure;
public sealed class KeyRetirementSafety(IKeyLifecycleRepository repo, KeyManagementOptions opts, TimeProvider clock) : IKeyRetirementSafety
{
    public async Task<RetirementSafetyAssessment> AssessAsync(string realm,string kid,CancellationToken ct){
        var r=new List<string>(); var m=await repo.GetAsync(realm,kid,ct);
        if(m is null) return new(kid,false,["key not found"]);
        if(m.State==KeyLifecycleState.Active) r.Add("key is still Active");
        if(m.State==KeyLifecycleState.Destroyed) r.Add("already Destroyed");
        if(m.State is KeyLifecycleState.Generated or KeyLifecycleState.VaultStored or KeyLifecycleState.Passive or KeyLifecycleState.Validated) r.Add($"key in state {m.State} not eligible for destroy");
        var graceEnd=(m.PassivatedAt??m.ActivatedAt??m.CreatedAt)+opts.GracePeriod+opts.RetentionAfterGrace;
        if(clock.GetUtcNow()<graceEnd) r.Add($"retention window not elapsed until {graceEnd:O}");
        return new(kid,r.Count==0,r);
    }
}
