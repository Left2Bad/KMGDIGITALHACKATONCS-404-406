using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public interface IActiveDirectoryClient
{
    LdapConnectionTestResult TestConnection(CancellationToken cancellationToken);

    IReadOnlyList<AdUserRecord> GetUsers(CancellationToken cancellationToken);

    IReadOnlyList<AdUserRecord> GetManagedServiceAccounts(CancellationToken cancellationToken);

    IReadOnlyList<AdGroupRecord> GetGroups(CancellationToken cancellationToken);
}
