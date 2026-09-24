using IdentityRiskAnalyzer.Web.Services.Objects;
using Microsoft.AspNetCore.Mvc;

namespace IdentityRiskAnalyzer.Web.Controllers;

[Route("Scans/{scanId:long}/Objects")]
public sealed class ScanObjectsController(ObjectDetailsQueryService details) : Controller
{
    [HttpGet("{objectGuid:guid}")]
    public async Task<IActionResult> Details(long scanId, Guid objectGuid, [FromQuery] int page = 1,
        CancellationToken cancellationToken = default)
    {
        var model = await details.GetAsync(scanId, objectGuid, page, cancellationToken);
        return model is null ? NotFound() : View(model);
    }
}
