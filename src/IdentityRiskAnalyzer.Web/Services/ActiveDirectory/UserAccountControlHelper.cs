using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public static class UserAccountControlHelper
{
    public static bool HasFlag(long userAccountControl, UserAccountControlFlags flag)
    {
        var mask = (long)flag;
        return mask != 0 && (userAccountControl & mask) == mask;
    }

    public static bool IsDisabled(long userAccountControl) =>
        HasFlag(userAccountControl, UserAccountControlFlags.AccountDisable);

    public static bool IsLocked(long? computedUserAccountControl) =>
        computedUserAccountControl.HasValue
        && HasFlag(computedUserAccountControl.Value, UserAccountControlFlags.Lockout);

    public static bool HasUnconstrainedDelegation(long userAccountControl) =>
        HasFlag(userAccountControl, UserAccountControlFlags.TrustedForDelegation);

    public static bool HasProtocolTransition(long userAccountControl) =>
        HasFlag(userAccountControl, UserAccountControlFlags.TrustedToAuthForDelegation);

    public static bool IsDelegationProtected(long userAccountControl) =>
        HasFlag(userAccountControl, UserAccountControlFlags.NotDelegated);
}
