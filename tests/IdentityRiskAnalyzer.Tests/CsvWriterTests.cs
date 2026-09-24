using System.Text;
using IdentityRiskAnalyzer.Web.Services.Export;

namespace IdentityRiskAnalyzer.Tests;

public sealed class CsvWriterTests
{
    [Fact]
    public void BasicRowUsesSemicolonAndCrLf()
    {
        var writer = new CsvWriter();
        writer.WriteRow(CsvField.Text("Alice"), CsvField.Text("Admin"), CsvField.Number(42));
        Assert.Equal("Alice;Admin;42\r\n", Read(writer));
    }

    [Theory]
    [InlineData("Hello;World", "\"Hello;World\"\r\n")]
    [InlineData("User \"Admin\"", "\"User \"\"Admin\"\"\"\r\n")]
    [InlineData("Line 1\r\nLine 2", "\"Line 1\r\nLine 2\"\r\n")]
    public void EscapesDelimiterQuotesAndLineBreaks(string input, string expected)
    {
        var writer = new CsvWriter();
        writer.WriteRow(CsvField.Text(input));
        Assert.Equal(expected, Read(writer));
    }

    [Fact]
    public void Utf8BomAndCyrillicRoundTrip()
    {
        var writer = new CsvWriter();
        writer.WriteRow(CsvField.Text("Проверить полномочия пользователя"));
        var bytes = writer.ToArray();
        Assert.Equal([0xEF, 0xBB, 0xBF], bytes[..3]);
        Assert.Equal("Проверить полномочия пользователя\r\n", Read(writer));
    }

    [Theory]
    [InlineData("=2+2", "'=2+2")]
    [InlineData("+SUM(A1:A2)", "'+SUM(A1:A2)")]
    [InlineData("-1+2", "'-1+2")]
    [InlineData("@SUM(A1:A2)", "'@SUM(A1:A2)")]
    [InlineData("  =HYPERLINK(\"x\")", "'  =HYPERLINK(\"x\")")]
    [InlineData("\t=2+2", "'\t=2+2")]
    [InlineData("\r=2+2", "'\r=2+2")]
    public void NeutralizesSpreadsheetFormulaText(string input, string expectedLogicalValue)
    {
        var writer = new CsvWriter();
        writer.WriteRow(CsvField.Text(input));
        var actual = Read(writer);
        Assert.Contains(expectedLogicalValue.Replace("\"", "\"\"", StringComparison.Ordinal), actual);
    }

    [Fact]
    public void OrdinaryTextAndTypedNumbersAreUnchanged()
    {
        var writer = new CsvWriter();
        writer.WriteRow(CsvField.Text("ivan.petrov"), CsvField.Number(-1), CsvField.Number(95),
            CsvField.Boolean(true), CsvField.Boolean((bool?)null));
        Assert.Equal("ivan.petrov;-1;95;true;\r\n", Read(writer));
    }

    [Fact]
    public void TimestampsUseInvariantIsoUtcAndNullableValuesStayEmpty()
    {
        var writer = new CsvWriter();
        writer.WriteRow(CsvField.Timestamp(new DateTimeOffset(2026, 9, 24, 19, 32, 17, TimeSpan.FromHours(5))),
            CsvField.Timestamp((DateTimeOffset?)null), CsvField.Boolean((bool?)false));
        Assert.Equal("2026-09-24T14:32:17Z;;false\r\n", Read(writer));
    }

    private static string Read(CsvWriter writer) => Encoding.UTF8.GetString(writer.ToArray()[3..]);
}
