using IdentityRiskAnalyzer.Web.Services.Export;
using Microsoft.AspNetCore.Mvc;

namespace IdentityRiskAnalyzer.Web.Controllers;

[Route("Scans/{scanId:long}/Export")]
public sealed class ScanExportsController(CsvExportService exports) : Controller
{
    private const string CsvContentType = "text/csv; charset=utf-8";

    [HttpGet("Accounts")]
    public async Task<IActionResult> Accounts(long scanId, CancellationToken cancellationToken)
    {
        var file = await exports.ExportAccountsAsync(scanId, cancellationToken);
        return file is null
            ? NotFound("This scan does not contain an exportable snapshot.")
            : File(file.Content, CsvContentType, file.FileName);
    }

    [HttpGet("Findings")]
    public async Task<IActionResult> Findings(long scanId, CancellationToken cancellationToken)
    {
        var file = await exports.ExportFindingsAsync(scanId, cancellationToken);
        return file is null
            ? NotFound("This scan does not contain an exportable snapshot.")
            : File(file.Content, CsvContentType, file.FileName);
    }
}
