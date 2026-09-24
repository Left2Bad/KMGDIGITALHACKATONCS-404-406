namespace IdentityRiskAnalyzer.Web.Domain.Enums;

public enum LdapConnectionErrorType
{
    None,
    Configuration,
    Network,
    Timeout,
    Authentication,
    BaseDn,
    Tls,
    Protocol,
    Unknown
}
