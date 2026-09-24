namespace IdentityRiskAnalyzer.Web.Domain.Enums;

[Flags]
public enum UserAccountControlFlags : long
{
    Lockout = 0x00000010,
    AccountDisable = 0x00000002,
    NormalAccount = 0x00000200,
    DontExpirePassword = 0x00010000,
    TrustedForDelegation = 0x00080000,
    NotDelegated = 0x00100000,
    TrustedToAuthForDelegation = 0x01000000
}
