namespace IdentityRiskAnalyzer.Web.Services.RiskRules;

public static class RiskRuleIds
{
    public const string StaleEnabledAccount = "IRA-ACCOUNT-001";
    public const string ExpiredAccount = "IRA-ACCOUNT-002";
    public const string LockedAccount = "IRA-ACCOUNT-003";
    public const string PasswordNeverExpires = "IRA-PASSWORD-001";
    public const string OldPassword = "IRA-PASSWORD-002";
    public const string ServicePasswordNeverExpires = "IRA-SERVICE-001";
    public const string DirectPrivilegedMembership = "IRA-PRIV-001";
    public const string NestedPrivilegedMembership = "IRA-PRIV-002";
    public const string MultipleAdministrativeRoles = "IRA-PRIV-003";
    public const string InactivePrivilegedAccount = "IRA-PRIV-004";
    public const string UnconstrainedDelegation = "IRA-DELEGATION-001";
    public const string ConstrainedDelegation = "IRA-DELEGATION-002";
    public const string ProtocolTransition = "IRA-DELEGATION-003";
    public const string ResourceBasedConstrainedDelegation = "IRA-DELEGATION-004";
    public const string SidHistoryPresent = "IRA-AD-001";
    public const string DuplicateSpn = "IRA-SPN-001";

    public static IReadOnlyList<string> All { get; } =
    [
        StaleEnabledAccount,
        ExpiredAccount,
        LockedAccount,
        PasswordNeverExpires,
        OldPassword,
        ServicePasswordNeverExpires,
        DirectPrivilegedMembership,
        NestedPrivilegedMembership,
        MultipleAdministrativeRoles,
        InactivePrivilegedAccount,
        UnconstrainedDelegation,
        ConstrainedDelegation,
        ProtocolTransition,
        ResourceBasedConstrainedDelegation,
        SidHistoryPresent,
        DuplicateSpn
    ];
}
