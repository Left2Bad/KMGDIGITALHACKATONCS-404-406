using System.Text;

namespace IdentityRiskAnalyzer.Web.Services.Export;

public sealed class CsvWriter
{
    public const char Delimiter = ';';
    private const string Newline = "\r\n";
    private static readonly UTF8Encoding Utf8WithBom = new(encoderShouldEmitUTF8Identifier: true);
    private readonly StringBuilder _builder = new();

    public void WriteRow(params CsvField[] fields)
    {
        for (var index = 0; index < fields.Length; index++)
        {
            if (index > 0) _builder.Append(Delimiter);
            var value = fields[index].Value ?? string.Empty;
            if (fields[index].IsText) value = NeutralizeFormula(value);
            if (value.IndexOfAny([Delimiter, '"', '\r', '\n']) >= 0)
            {
                _builder.Append('"').Append(value.Replace("\"", "\"\"", StringComparison.Ordinal)).Append('"');
            }
            else
            {
                _builder.Append(value);
            }
        }
        _builder.Append(Newline);
    }

    public byte[] ToArray()
    {
        var content = Utf8WithBom.GetBytes(_builder.ToString());
        var preamble = Utf8WithBom.GetPreamble();
        var bytes = new byte[preamble.Length + content.Length];
        preamble.CopyTo(bytes, 0);
        content.CopyTo(bytes, preamble.Length);
        return bytes;
    }

    private static string NeutralizeFormula(string value)
    {
        if (value.Length == 0) return value;
        if (value[0] is '\t' or '\r' or '\n') return "'" + value;

        var firstSignificant = 0;
        while (firstSignificant < value.Length && char.IsWhiteSpace(value[firstSignificant])) firstSignificant++;
        return firstSignificant < value.Length && value[firstSignificant] is '=' or '+' or '-' or '@'
            ? "'" + value
            : value;
    }
}
