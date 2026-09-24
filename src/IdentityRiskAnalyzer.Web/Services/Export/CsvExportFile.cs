namespace IdentityRiskAnalyzer.Web.Services.Export;

public sealed record CsvExportFile(byte[] Content, string FileName, int Rows);
