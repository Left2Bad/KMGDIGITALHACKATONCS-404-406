using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.SecurityEvents;

public interface ISecurityEventLogCollector
{
    SecurityEventCollectionResult Collect(CancellationToken cancellationToken);
}
