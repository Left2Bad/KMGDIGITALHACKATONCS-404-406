using System.Net;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.ViewModels;

namespace IdentityRiskAnalyzer.Tests;

public class ActiveDirectorySecurityModelTests
{
    [Fact]
    public void ViewModelIndicatesCredentialsWithoutExposingThem()
    {
        const string password = "example-secret-value";
        var options = new ActiveDirectoryOptions
        {
            Server = "dc01.adlab.test",
            BaseDn = "DC=adlab,DC=test",
            Username = "ADLAB\\svc_ira_scanner",
            Password = password
        };

        var viewModel = ActiveDirectoryConnectionViewModel.From(options);
        var stringValues = typeof(ActiveDirectoryConnectionViewModel)
            .GetProperties()
            .Select(property => property.GetValue(viewModel))
            .OfType<string>();

        Assert.True(viewModel.CredentialsConfigured);
        Assert.DoesNotContain(password, stringValues);
        Assert.Null(typeof(ActiveDirectoryConnectionViewModel).GetProperty(nameof(ActiveDirectoryOptions.Password)));
        Assert.Null(typeof(ActiveDirectoryConnectionViewModel).GetProperty(nameof(ActiveDirectoryOptions.Username)));
    }

    [Fact]
    public void ConnectionResultDoesNotContainCredentials()
    {
        var properties = typeof(LdapConnectionTestResult).GetProperties();

        Assert.DoesNotContain(properties, property => property.Name.Contains("Password", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(properties, property => typeof(NetworkCredential).IsAssignableFrom(property.PropertyType));
    }
}
