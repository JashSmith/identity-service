using Identity.Domain;
namespace Identity.Domain.Tests;
public sealed class KeyLifecycleTests
{
    [Fact] public void Valid_transitions_pass(){Assert.True(KeyLifecycleTransitions.CanTransition(KeyLifecycleState.Generated, KeyLifecycleState.VaultStored));}
    [Fact] public void Invalid_transition_throws(){Assert.Throws<InvalidOperationException>(()=>KeyLifecycleTransitions.Ensure(KeyLifecycleState.Active, KeyLifecycleState.Destroyed));}
    [Fact] public void Passive_cannot_be_destroyed_via_shortcut(){Assert.Throws<InvalidOperationException>(()=>KeyLifecycleTransitions.Ensure(KeyLifecycleState.Active, KeyLifecycleState.Retired));}
    [Fact] public void SigningKeyMetadata_With_updates_timestamps(){var now=DateTimeOffset.UtcNow; var m=new SigningKeyMetadata("k",RsaKeySize.Rsa2048,"sha256:abc","p",1,KeyLifecycleState.Validated,now,"company"); var n=m.With(KeyLifecycleState.Active,now.AddMinutes(1),"actor"); Assert.Equal(KeyLifecycleState.Active,n.State); Assert.NotNull(n.ActivatedAt);}
    [Fact] public void Kid_immutability_second_creation_fails_via_transition(){Assert.Throws<InvalidOperationException>(()=>KeyLifecycleTransitions.Ensure(KeyLifecycleState.Destroyed, KeyLifecycleState.Generated));}
    [Fact] public void Destroyed_has_no_outgoing(){Assert.False(KeyLifecycleTransitions.CanTransition(KeyLifecycleState.Destroyed, KeyLifecycleState.Active));}
}
