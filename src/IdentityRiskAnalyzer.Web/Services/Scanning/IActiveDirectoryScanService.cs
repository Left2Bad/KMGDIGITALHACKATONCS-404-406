using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.Scanning;

public interface IActiveDirectoryScanService
{
    Task<ScanExecutionResult> RunScanAsync(CancellationToken cancellationToken);
}
