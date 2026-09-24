using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;

namespace IdentityRiskAnalyzer.Web.ViewModels;

public sealed class ActiveDirectoryConnectionViewModel
{
    public string Server { get; init; } = string.Empty;
    public int Port { get; init; }
    public string Protocol { get; init; } = "LDAP";
    public string BaseDn { get; init; } = string.Empty;
    public int TimeoutSeconds { get; init; }
    public bool CredentialsConfigured { get; init; }
    public LdapConnectionTestResult? TestResult { get; init; }

    public static ActiveDirectoryConnectionViewModel From(
        ActiveDirectoryOptions options,
        LdapConnectionTestResult? testResult = null) => new()
        {
            Server = options.Server,
            Port = options.Port,
            Protocol = options.UseSsl ? "LDAPS" : "LDAP",
            BaseDn = options.BaseDn,
            TimeoutSeconds = options.ConnectTimeoutSeconds,
            CredentialsConfigured = options.CredentialsConfigured,
            TestResult = testResult
        };
}
