using System.Globalization;

namespace IdentityRiskAnalyzer.Web.Services.Export;

// Text fields are untrusted and receive spreadsheet-formula protection.
// Typed numeric, boolean, and timestamp values retain machine-readable forms.
public readonly record struct CsvField(string? Value, bool IsText)
{
    public static CsvField Text(string? value) => new(value, true);
    public static CsvField Number(int value) => new(value.ToString(CultureInfo.InvariantCulture), false);
    public static CsvField Number(long value) => new(value.ToString(CultureInfo.InvariantCulture), false);
    public static CsvField Boolean(bool value) => new(value ? "true" : "false", false);
    public static CsvField Boolean(bool? value) => value.HasValue ? Boolean(value.Value) : new(null, false);
    public static CsvField Timestamp(DateTimeOffset value) => new(
        value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.FFFFFFF'Z'", CultureInfo.InvariantCulture), false);
    public static CsvField Timestamp(DateTimeOffset? value) => value.HasValue ? Timestamp(value.Value) : new(null, false);
}
