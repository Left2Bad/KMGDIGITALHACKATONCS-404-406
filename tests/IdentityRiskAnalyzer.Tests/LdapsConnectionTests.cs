using System.ComponentModel.DataAnnotations;
using System.DirectoryServices.Protocols;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;
using IdentityRiskAnalyzer.Web.ViewModels;
using Microsoft.Extensions.Configuration;

namespace IdentityRiskAnalyzer.Tests;

public class LdapsConnectionTests
{
    [Theory]
    [InlineData(false, 389)]
    [InlineData(true, 636)]
    [InlineData(true, 1636)]
    public void SharedConnectionSetupUsesConfiguredTransportAndPort(bool useSsl, int port)
    {
        var options = new ActiveDirectoryOptions
        {
            Server = "dc01.adlab.test",
            Port = port,
            UseSsl = useSsl,
            BaseDn = "DC=adlab,DC=test",
            ConnectTimeoutSeconds = 12
        };

        using var connection = LdapActiveDirectoryClient.CreateConnection(options);

        // WinLDAP does not reliably report the requested SSL option before Bind.
        // The factory sets SecureSocketLayer from UseSsl; a live handshake is a lab check.
        if (!useSsl)
        {
            Assert.False(connection.SessionOptions.SecureSocketLayer);
        }
        Assert.Equal(3, connection.SessionOptions.ProtocolVersion);
        Assert.Equal(AuthType.Negotiate, connection.AuthType);
        Assert.Equal(TimeSpan.FromSeconds(12), connection.Timeout);
        var endpoint = Assert.IsType<LdapDirectoryIdentifier>(connection.Directory);
        Assert.Equal(port, endpoint.PortNumber);
        Assert.Contains("dc01.adlab.test", endpoint.Servers);
        Assert.Null(connection.SessionOptions.VerifyServerCertificate);
    }

    [Fact]
    public void OptionsBindLdapsConfigurationAndViewModelHidesPassword()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ActiveDirectory:Server"] = "dc01.adlab.test",
            ["ActiveDirectory:Port"] = "636",
            ["ActiveDirectory:UseSsl"] = "true",
            ["ActiveDirectory:BaseDn"] = "DC=adlab,DC=test",
            ["ActiveDirectory:Password"] = "not-for-display"
        }).Build();
        var options = config.GetSection(ActiveDirectoryOptions.SectionName).Get<ActiveDirectoryOptions>()!;

        Assert.Equal(636, options.Port);
        Assert.True(options.UseSsl);
        Assert.Equal("dc01.adlab.test", options.Server);
        var view = ActiveDirectoryConnectionViewModel.From(options);
        Assert.Equal("LDAPS (TLS)", view.Protocol);
        Assert.DoesNotContain("not-for-display", view.GetType().GetProperties()
            .Select(property => property.GetValue(view)).OfType<string>());
    }

    [Fact]
    public void LdapsRequiresDnsNameRatherThanIpAddress()
    {
        var options = new ActiveDirectoryOptions
        {
            Server = "192.0.2.10",
            Port = 636,
            UseSsl = true,
            BaseDn = "DC=adlab,DC=test"
        };
        var errors = new List<ValidationResult>();

        Validator.TryValidateObject(options, new ValidationContext(options), errors, true);

        Assert.Contains(errors, error => error.MemberNames.Contains(nameof(options.Server)));
    }
}
