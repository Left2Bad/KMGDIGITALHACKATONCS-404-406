using System.ComponentModel.DataAnnotations;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;
using IdentityRiskAnalyzer.Web.ViewModels;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Tests;

public sealed class ServiceAccountClassifierTests
{
    [Fact]
    public void OrdinaryUserIsNotAServiceAccount()
    {
        var result = Classify(User("ivan.petrov", objectClasses: ["top", "person", "organizationalPerson", "user"]));

        Assert.False(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.None, result.DetectionMethod);
        Assert.Equal(ServiceAccountDetectionConfidence.None, result.Confidence);
        Assert.Empty(result.Evidence);
    }

    [Fact]
    public void SpnIsAHighConfidenceServiceAccountSignal()
    {
        var result = Classify(User("sql_service", spns: ["MSSQLSvc/sql01"]));

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.ServicePrincipalName, result.DetectionMethod);
        Assert.Equal(ServiceAccountDetectionConfidence.High, result.Confidence);
        Assert.Contains("Account has 1 Service Principal Name(s).", result.Evidence);
        Assert.Equal(["MSSQLSvc/sql01"], result.ServicePrincipalNames);
    }

    [Fact]
    public void KeepsMultipleSpnsForDetailEvidence()
    {
        var result = Classify(User("web_service", spns: ["HTTP/app01", "HTTP/app01.adlab.test"]));

        Assert.True(result.IsServiceAccount);
        Assert.Equal(2, result.ServicePrincipalNames.Count);
        Assert.Contains("Account has 2 Service Principal Name(s).", result.Evidence);
    }

    [Fact]
    public void NamePatternIsOnlyAHeuristic()
    {
        var result = Classify(User("svc_backup"));

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.NameHeuristic, result.DetectionMethod);
        Assert.Equal(ServiceAccountDetectionConfidence.Heuristic, result.Confidence);
        Assert.Contains("Account name matches configured pattern: svc_*", result.Evidence);
    }

    [Fact]
    public void CanDisableNameHeuristics()
    {
        var result = Classify(User("svc_backup"), enableHeuristics: false);

        Assert.False(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.None, result.DetectionMethod);
    }

    [Fact]
    public void SupportsCustomWildcardPattern()
    {
        var result = Classify(User("robot-backup"), patterns: ["robot-*"]);

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.NameHeuristic, result.DetectionMethod);
        Assert.Contains("Account name matches configured pattern: robot-*", result.Evidence);
    }

    [Fact]
    public void MatchesNamePatternsCaseInsensitively()
    {
        var result = Classify(User("svc_sql"), patterns: ["SVC_*"]);

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.NameHeuristic, result.DetectionMethod);
    }

    [Fact]
    public void SupportsWildcardAtBothEndsWithoutRegex()
    {
        var result = Classify(User("robot-backup-prod"), patterns: ["*backup*"]);

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.NameHeuristic, result.DetectionMethod);
    }

    [Fact]
    public void ClassifiesManagedServiceAccountAsDefinitive()
    {
        var result = Classify(User("sql_msa", objectClasses: ["top", "computer", "msDS-ManagedServiceAccount"]));

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.ManagedServiceAccount, result.DetectionMethod);
        Assert.Equal(ServiceAccountDetectionConfidence.Definitive, result.Confidence);
        Assert.Contains("Object class includes msDS-ManagedServiceAccount.", result.Evidence);
    }

    [Fact]
    public void ClassifiesGroupManagedServiceAccountAsDefinitiveWithoutDoubleCountingItsBaseClass()
    {
        var result = Classify(User(
            "sql_gmsa$",
            objectClasses: ["top", "computer", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"]));

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.GroupManagedServiceAccount, result.DetectionMethod);
        Assert.Equal(ServiceAccountDetectionConfidence.Definitive, result.Confidence);
        Assert.Contains("Object class includes msDS-GroupManagedServiceAccount.", result.Evidence);
        Assert.DoesNotContain(result.Evidence, evidence => evidence == "Object class includes msDS-ManagedServiceAccount.");
    }

    [Fact]
    public void ReportsMultipleSignalsAndKeepsStrongestConfidence()
    {
        var result = Classify(User("svc_sql", spns: ["MSSQLSvc/sql01"]));

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.MultipleSignals, result.DetectionMethod);
        Assert.Equal(ServiceAccountDetectionConfidence.High, result.Confidence);
        Assert.Contains(result.Evidence, evidence => evidence.Contains("Service Principal Name", StringComparison.Ordinal));
        Assert.Contains(result.Evidence, evidence => evidence.Contains("svc_*", StringComparison.Ordinal));
    }

    [Fact]
    public void DisabledServiceAccountIsStillClassified()
    {
        var result = Classify(User(
            "svc_backup",
            userAccountControl: (long)UserAccountControlFlags.AccountDisable,
            spns: ["BackupSvc/host01"]));

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.MultipleSignals, result.DetectionMethod);
    }

    [Fact]
    public void SpnDetectionWorksWithoutSamAccountName()
    {
        var result = Classify(User(null, userPrincipalName: "service@app.adlab.test", spns: ["HTTP/app01"]));

        Assert.True(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.ServicePrincipalName, result.DetectionMethod);
        Assert.Equal("service@app.adlab.test", result.AccountName);
    }

    [Fact]
    public void EmptyPatternConfigurationIsSafe()
    {
        var result = Classify(User("svc_backup"), patterns: []);

        Assert.False(result.IsServiceAccount);
    }

    [Fact]
    public void PasswordExpiryAndDelegationSettingsDoNotClassifyAnAccount()
    {
        var user = new AdUserRecord
        {
            ObjectGuid = Guid.NewGuid(),
            DistinguishedName = "CN=ivan.petrov,OU=Users,DC=adlab,DC=test",
            SamAccountName = "ivan.petrov",
            UserAccountControl = (long)UserAccountControlFlags.NormalAccount | (long)UserAccountControlFlags.DontExpirePassword,
            AllowedToDelegateTo = ["HTTP/app01"],
            HasResourceBasedConstrainedDelegation = true
        };

        var result = Classify(user);

        Assert.False(result.IsServiceAccount);
        Assert.Equal(ServiceAccountDetectionMethod.None, result.DetectionMethod);
    }

    [Fact]
    public void BatchClassificationIsLocalAndReturnsEveryAccount()
    {
        var users = new[] { User("svc_app", spns: ["HTTP/app01"]), User("ivan.petrov") };

        var results = CreateClassifier().ClassifyAll(users);

        Assert.Equal(2, results.Count);
        Assert.True(Assert.Single(results, result => result.ObjectGuid == users[0].ObjectGuid).IsServiceAccount);
        Assert.False(Assert.Single(results, result => result.ObjectGuid == users[1].ObjectGuid).IsServiceAccount);
    }

    [Fact]
    public void DetailViewModelShowsHeuristicAsPossibleAndDisclosesInteractivePolicyLimit()
    {
        var viewModel = ServiceAccountClassificationViewModel.From(Classify(User("svc_backup")));

        Assert.Equal("Possible", viewModel.Status);
        Assert.Equal("Name heuristic", viewModel.DetectionMethod);
        Assert.Equal("Heuristic", viewModel.Confidence);
        Assert.Equal("Not evaluated in this MVP.", viewModel.InteractiveLogonPolicyStatus);
    }

    [Fact]
    public void OptionsAllowEmptyPatternsAndRejectUnboundedCatchAllPatterns()
    {
        var empty = new ServiceAccountAnalysisOptions { NamePatterns = [] };
        var invalid = new ServiceAccountAnalysisOptions { NamePatterns = ["*"] };

        Assert.Empty(empty.Validate(new ValidationContext(empty)));
        Assert.NotEmpty(invalid.Validate(new ValidationContext(invalid)));
    }

    private static ServiceAccountClassification Classify(
        AdUserRecord user,
        IReadOnlyCollection<string>? patterns = null,
        bool enableHeuristics = true) => CreateClassifier(patterns, enableHeuristics).Classify(user);

    private static ServiceAccountClassifier CreateClassifier(
        IReadOnlyCollection<string>? patterns = null,
        bool enableHeuristics = true) => new(
        NullLogger<ServiceAccountClassifier>.Instance,
        Options.Create(new ServiceAccountAnalysisOptions
        {
            EnableNameHeuristics = enableHeuristics,
            NamePatterns = patterns?.ToList() ?? ["svc_*", "service_*", "sa_*"]
        }));

    private static AdUserRecord User(
        string? samAccountName,
        string? userPrincipalName = null,
        long userAccountControl = (long)UserAccountControlFlags.NormalAccount,
        IReadOnlyList<string>? spns = null,
        IReadOnlyList<string>? objectClasses = null) => new()
    {
        ObjectGuid = Guid.NewGuid(),
        DistinguishedName = $"CN={samAccountName ?? "missing"},OU=Users,DC=adlab,DC=test",
        SamAccountName = samAccountName,
        UserPrincipalName = userPrincipalName,
        UserAccountControl = userAccountControl,
        ServicePrincipalNames = spns ?? Array.Empty<string>(),
        ObjectClasses = objectClasses ?? ["top", "person", "organizationalPerson", "user"]
    };
}
