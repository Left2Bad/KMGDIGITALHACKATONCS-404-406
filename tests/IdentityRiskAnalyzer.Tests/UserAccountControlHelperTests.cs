using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Tests;

public sealed class UserAccountControlHelperTests
{
    [Fact]
    public void ReportsFlagAsAbsentWhenMaskIsNotSet()
    {
        Assert.False(UserAccountControlHelper.HasFlag(0, UserAccountControlFlags.AccountDisable));
        Assert.False(UserAccountControlHelper.IsDisabled(0));
        Assert.False(UserAccountControlHelper.HasUnconstrainedDelegation((long)UserAccountControlFlags.NormalAccount));
        Assert.False(UserAccountControlHelper.IsLocked(null));
        Assert.False(UserAccountControlHelper.IsLocked(0));
    }

    [Fact]
    public void ReportsIndividualFlagsWhenSet()
    {
        Assert.True(UserAccountControlHelper.IsDisabled((long)UserAccountControlFlags.AccountDisable));
        Assert.True(UserAccountControlHelper.HasUnconstrainedDelegation((long)UserAccountControlFlags.TrustedForDelegation));
        Assert.True(UserAccountControlHelper.HasProtocolTransition((long)UserAccountControlFlags.TrustedToAuthForDelegation));
        Assert.True(UserAccountControlHelper.IsDelegationProtected((long)UserAccountControlFlags.NotDelegated));
        Assert.True(UserAccountControlHelper.HasFlag((long)UserAccountControlFlags.DontExpirePassword, UserAccountControlFlags.DontExpirePassword));
        Assert.True(UserAccountControlHelper.IsLocked((long)UserAccountControlFlags.Lockout));
    }

    [Fact]
    public void DetectsCombinedFlagsWithoutConfusingThem()
    {
        var value = (long)(UserAccountControlFlags.AccountDisable | UserAccountControlFlags.TrustedForDelegation);

        Assert.True(UserAccountControlHelper.HasFlag(value, UserAccountControlFlags.AccountDisable | UserAccountControlFlags.TrustedForDelegation));
        Assert.True(UserAccountControlHelper.IsDisabled(value));
        Assert.True(UserAccountControlHelper.HasUnconstrainedDelegation(value));
        Assert.False(UserAccountControlHelper.HasProtocolTransition(value));
        Assert.True(UserAccountControlHelper.IsLocked((long)(UserAccountControlFlags.Lockout | UserAccountControlFlags.NormalAccount)));
    }

    [Fact]
    public void ZeroIsNotTreatedAsContainingTheZeroMask()
    {
        Assert.False(UserAccountControlHelper.HasFlag(long.MaxValue, 0));
    }
}
