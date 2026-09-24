using System.Security.Principal;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Tests;

public class ActiveDirectoryAttributeConverterTests
{
    [Fact]
    public void ConvertsActiveDirectoryGuidBytes()
    {
        byte[] bytes = [0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        Assert.Equal(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
            ActiveDirectoryAttributeConverter.ConvertGuid(bytes));
    }

    [Fact]
    public void ReturnsNullForMissingOrMalformedGuid()
    {
        Assert.Null(ActiveDirectoryAttributeConverter.ConvertGuid(null));
        Assert.Null(ActiveDirectoryAttributeConverter.ConvertGuid(new byte[15]));
        Assert.Null(ActiveDirectoryAttributeConverter.ConvertGuid("not-a-binary-guid"));
    }

    [Fact]
    public void ConvertsBinarySidToStandardString()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var expected = new SecurityIdentifier("S-1-5-18");
        var bytes = new byte[expected.BinaryLength];
        expected.GetBinaryForm(bytes, 0);

        Assert.Equal("S-1-5-18", ActiveDirectoryAttributeConverter.ConvertSid(bytes));
    }

    [Fact]
    public void ReturnsNullForMissingOrMalformedSid()
    {
        Assert.Null(ActiveDirectoryAttributeConverter.ConvertSid(null));
        Assert.Null(ActiveDirectoryAttributeConverter.ConvertSid(Array.Empty<byte>()));
        Assert.Null(ActiveDirectoryAttributeConverter.ConvertSid(new byte[] { 1 }));
    }

    [Fact]
    public void ConvertsFileTimeToUtc()
    {
        var expected = new DateTimeOffset(2020, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var fileTime = expected.UtcDateTime.ToFileTimeUtc();

        var result = ActiveDirectoryAttributeConverter.ConvertFileTime(fileTime.ToString());

        Assert.Equal(expected, result);
        Assert.Equal(TimeSpan.Zero, result!.Value.Offset);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(long.MaxValue)]
    public void TreatsFileTimeSentinelsAsNoDate(long fileTime)
    {
        Assert.Null(ActiveDirectoryAttributeConverter.ConvertFileTime(fileTime));
    }

    [Fact]
    public void TreatsMissingFileTimeAsNoDate()
    {
        Assert.Null(ActiveDirectoryAttributeConverter.ConvertFileTime(null));
    }

    [Theory]
    [InlineData("not-a-number")]
    [InlineData("-1")]
    public void HandlesMalformedFileTimeWithoutThrowing(string rawValue)
    {
        Assert.Null(ActiveDirectoryAttributeConverter.ConvertFileTime(rawValue));
        Assert.False(ActiveDirectoryAttributeConverter.TryConvertFileTime(rawValue, out _));
    }

    [Fact]
    public void ConvertsMissingAndEmptyMultivalueAttributesToEmptyList()
    {
        Assert.Empty(ActiveDirectoryAttributeConverter.ConvertStringValues(null));
        Assert.Empty(ActiveDirectoryAttributeConverter.ConvertStringValues(Array.Empty<object?>()));
    }

    [Fact]
    public void ConvertsSingleAndMultipleStringValues()
    {
        Assert.Equal(
            new[] { "CN=HelpDesk,DC=adlab,DC=test" },
            ActiveDirectoryAttributeConverter.ConvertStringValues(["CN=HelpDesk,DC=adlab,DC=test"]));

        Assert.Equal(
            new[] { "HTTP/app01.adlab.test", "MSSQLSvc/sql01.adlab.test:1433" },
            ActiveDirectoryAttributeConverter.ConvertStringValues(
                ["HTTP/app01.adlab.test", "MSSQLSvc/sql01.adlab.test:1433"]));
    }
}
