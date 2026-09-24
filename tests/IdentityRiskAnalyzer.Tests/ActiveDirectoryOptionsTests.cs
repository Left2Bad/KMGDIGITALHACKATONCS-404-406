using System.ComponentModel.DataAnnotations;
using IdentityRiskAnalyzer.Web.Options;

namespace IdentityRiskAnalyzer.Tests;

public class ActiveDirectoryOptionsTests
{
    [Theory]
    [InlineData("", 389, "DC=adlab,DC=test", 10, "Server")]
    [InlineData("dc01.adlab.test", 0, "DC=adlab,DC=test", 10, "Port")]
    [InlineData("dc01.adlab.test", 389, "", 10, "BaseDn")]
    [InlineData("dc01.adlab.test", 389, "DC=adlab,DC=test", 0, "ConnectTimeoutSeconds")]
    public void RejectsInvalidConnectionSettings(
        string server,
        int port,
        string baseDn,
        int timeoutSeconds,
        string expectedMember)
    {
        var options = new ActiveDirectoryOptions
        {
            Server = server,
            Port = port,
            BaseDn = baseDn,
            ConnectTimeoutSeconds = timeoutSeconds
        };

        var results = Validate(options);

        Assert.Contains(results, result => result.MemberNames.Contains(expectedMember));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1001)]
    public void RejectsOutOfRangePageSize(int pageSize)
    {
        var options = new ActiveDirectoryOptions
        {
            Server = "dc01.adlab.test",
            BaseDn = "DC=adlab,DC=test",
            PageSize = pageSize
        };

        Assert.Contains(Validate(options), result => result.MemberNames.Contains(nameof(options.PageSize)));
    }

    [Fact]
    public void AcceptsValidConnectionSettings()
    {
        var options = new ActiveDirectoryOptions
        {
            Server = "dc01.adlab.test",
            Port = 389,
            BaseDn = "DC=adlab,DC=test",
            ConnectTimeoutSeconds = 10
        };

        Assert.Empty(Validate(options));
    }

    [Fact]
    public void RejectsOnlyOneExplicitCredential()
    {
        var options = new ActiveDirectoryOptions
        {
            Server = "dc01.adlab.test",
            BaseDn = "DC=adlab,DC=test",
            Username = "ADLAB\\svc_ira_scanner"
        };

        Assert.Contains(Validate(options), result => result.MemberNames.Contains(nameof(options.Password)));
    }

    private static List<ValidationResult> Validate(ActiveDirectoryOptions options)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(options, new ValidationContext(options), results, validateAllProperties: true);
        return results;
    }
}
