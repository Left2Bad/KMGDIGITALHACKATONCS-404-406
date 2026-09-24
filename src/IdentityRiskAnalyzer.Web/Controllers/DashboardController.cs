using IdentityRiskAnalyzer.Web.Services.Dashboard;
using Microsoft.AspNetCore.Mvc;

namespace IdentityRiskAnalyzer.Web.Controllers;

public sealed class DashboardController(DashboardQueryService dashboard) : Controller
{
    [HttpGet("/")]
    [HttpGet("/Dashboard")]
    public async Task<IActionResult> Index(CancellationToken cancellationToken) =>
        View(await dashboard.GetDashboardAsync(cancellationToken));
}
