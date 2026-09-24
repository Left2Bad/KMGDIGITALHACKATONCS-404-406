using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Services.Delegation;
using Microsoft.Extensions.Logging.Abstractions;

namespace IdentityRiskAnalyzer.Tests;

public sealed class DelegationAnalyzerTests
{
    [Fact]
    public void ReturnsNoResultsWhenUserHasNoDelegationSettings()
    {
        var result = CreateAnalyzer().Analyze(User());

        Assert.Empty(result);
    }

    [Fact]
    public void DetectsUnconstrainedDelegationFromUserAccountControl()
    {
        var user = User((long)UserAccountControlFlags.TrustedForDelegation);

        var result = Assert.Single(CreateAnalyzer().Analyze(user));

        Assert.Equal(DelegationType.Unconstrained, result.DelegationType);
        Assert.Empty(result.Targets);
        Assert.Contains("TRUSTED_FOR_DELEGATION", result.Evidence, StringComparison.Ordinal);
        Assert.False(result.RequiresDetailedReview);
    }

    [Fact]
    public void DetectsConstrainedDelegationAndReturnsItsTargets()
    {
        var user = User(allowedToDelegateTo: ["HTTP/app01.adlab.test"]);

        var result = Assert.Single(CreateAnalyzer().Analyze(user));

        Assert.Equal(DelegationType.Constrained, result.DelegationType);
        Assert.Equal(["HTTP/app01.adlab.test"], result.Targets);
        Assert.Contains("msDS-AllowedToDelegateTo", result.Evidence, StringComparison.Ordinal);
        Assert.False(result.RequiresDetailedReview);
    }

    [Fact]
    public void ReturnsAllConstrainedTargets()
    {
        var targets = new[] { "HTTP/app01", "MSSQLSvc/sql01", "CIFS/file01" };

        var result = Assert.Single(CreateAnalyzer().Analyze(User(allowedToDelegateTo: targets)));

        Assert.Equal(targets, result.Targets);
        Assert.Contains("3 target service(s)", result.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void ProtocolTransitionTakesPrecedenceOverConstrainedForTheSameTargets()
    {
        var user = User(
            (long)UserAccountControlFlags.TrustedToAuthForDelegation,
            ["HTTP/app01.adlab.test"]);

        var result = Assert.Single(CreateAnalyzer().Analyze(user));

        Assert.Equal(DelegationType.ProtocolTransition, result.DelegationType);
        Assert.Equal(["HTTP/app01.adlab.test"], result.Targets);
        Assert.Contains("TRUSTED_TO_AUTH_FOR_DELEGATION", result.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain(CreateAnalyzer().Analyze(user), item => item.DelegationType == DelegationType.Constrained);
    }

    [Fact]
    public void ProtocolTransitionFlagWithoutTargetsDoesNotInventDelegationTarget()
    {
        var user = User((long)UserAccountControlFlags.TrustedToAuthForDelegation);

        Assert.Empty(CreateAnalyzer().Analyze(user));
    }

    [Fact]
    public void DetectsRbcdPresenceAndRequestsDetailedReview()
    {
        var user = User(hasRbcd: true);

        var result = Assert.Single(CreateAnalyzer().Analyze(user));

        Assert.Equal(DelegationType.ResourceBasedConstrained, result.DelegationType);
        Assert.True(result.RequiresDetailedReview);
        Assert.Empty(result.Targets);
        Assert.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity", result.Evidence, StringComparison.Ordinal);
        Assert.Contains("ACL parsing is not implemented", result.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void PreservesIndependentUnconstrainedAndRbcdMechanisms()
    {
        var user = User((long)UserAccountControlFlags.TrustedForDelegation, hasRbcd: true);

        var results = CreateAnalyzer().Analyze(user);

        Assert.Equal(
            [DelegationType.Unconstrained, DelegationType.ResourceBasedConstrained],
            results.Select(result => result.DelegationType));
    }

    [Fact]
    public void NotDelegatedByItselfDoesNotCreateDangerousDelegationResult()
    {
        var user = User((long)UserAccountControlFlags.NotDelegated);

        Assert.Empty(CreateAnalyzer().Analyze(user));
    }

    [Fact]
    public void DeduplicatesTargetsCaseInsensitivelyAndPreservesFirstValue()
    {
        var user = User(allowedToDelegateTo:
        [
            "HTTP/App01.adlab.test",
            "http/app01.adlab.test",
            "MSSQLSvc/sql01.adlab.test",
            "HTTP/App01.adlab.test"
        ]);

        var result = Assert.Single(CreateAnalyzer().Analyze(user));

        Assert.Equal(["HTTP/App01.adlab.test", "MSSQLSvc/sql01.adlab.test"], result.Targets);
    }

    [Fact]
    public void EveryDetectedMechanismHasUsefulEvidenceAndObjectIdentity()
    {
        var user = User((long)UserAccountControlFlags.TrustedForDelegation, hasRbcd: true);

        var results = CreateAnalyzer().Analyze(user);

        Assert.Equal(2, results.Count);
        Assert.All(results, result =>
        {
            Assert.NotEqual(Guid.Empty, result.ObjectGuid);
            Assert.Equal("svc_app", result.ObjectName);
            Assert.Equal(user.DistinguishedName, result.DistinguishedName);
            Assert.False(string.IsNullOrWhiteSpace(result.Evidence));
        });
    }

    [Fact]
    public void BatchAnalysisReturnsMechanismsForEachUserWithoutLdapAccess()
    {
        var users = new[]
        {
            User((long)UserAccountControlFlags.TrustedForDelegation),
            User(allowedToDelegateTo: ["HTTP/app01"]),
            User()
        };

        var results = CreateAnalyzer().AnalyzeAll(users);

        Assert.Equal(2, results.Count);
        Assert.Contains(results, result => result.ObjectGuid == users[0].ObjectGuid && result.DelegationType == DelegationType.Unconstrained);
        Assert.Contains(results, result => result.ObjectGuid == users[1].ObjectGuid && result.DelegationType == DelegationType.Constrained);
    }

    private static DelegationAnalyzer CreateAnalyzer() => new(NullLogger<DelegationAnalyzer>.Instance);

    private static AdUserRecord User(
        long userAccountControl = (long)UserAccountControlFlags.NormalAccount,
        IReadOnlyList<string>? allowedToDelegateTo = null,
        bool hasRbcd = false) => new()
    {
        ObjectGuid = Guid.NewGuid(),
        SamAccountName = "svc_app",
        DistinguishedName = "CN=svc_app,OU=Service Accounts,DC=adlab,DC=test",
        UserAccountControl = userAccountControl,
        AllowedToDelegateTo = allowedToDelegateTo ?? Array.Empty<string>(),
        HasResourceBasedConstrainedDelegation = hasRbcd
    };
}
