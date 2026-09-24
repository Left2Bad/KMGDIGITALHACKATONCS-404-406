using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;
using IdentityRiskAnalyzer.Web.Services.Delegation;
using IdentityRiskAnalyzer.Web.Services.RiskRules;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Account;
using IdentityRiskAnalyzer.Web.Services.RiskRules.ActiveDirectory;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Delegation;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Password;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Privilege;
using IdentityRiskAnalyzer.Web.Services.RiskRules.ServiceAccount;
using IdentityRiskAnalyzer.Web.Services.RiskRules.Spn;
using Microsoft.Extensions.Logging.Abstractions;

namespace IdentityRiskAnalyzer.Tests;

public sealed class RiskRuleEngineTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(89, false)]
    [InlineData(90, true)]
    [InlineData(91, true)]
    public void StaleEnabledAccountUsesInclusiveConfiguredThreshold(int inactiveDays, bool expected)
    {
        var context = Context(user: User(lastActivity: Now.AddDays(-inactiveDays)));

        Assert.Equal(expected, Evaluate(new StaleEnabledAccountRule(), context).Count > 0);
    }

    [Fact]
    public void StaleAccountRuleSkipsDisabledAndUnknownActivityAccounts()
    {
        Assert.Empty(Evaluate(new StaleEnabledAccountRule(), Context(user: User(
            uac: (long)UserAccountControlFlags.AccountDisable,
            lastActivity: Now.AddDays(-365)))));
        Assert.Empty(Evaluate(new StaleEnabledAccountRule(), Context(user: User(lastActivity: null))));
    }

    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    [InlineData(1, false)]
    public void ExpiredAccountRuleUsesStrictExpirationComparison(int expirationDayOffset, bool expected)
    {
        var context = Context(user: User(accountExpires: Now.AddDays(expirationDayOffset)));

        Assert.Equal(expected, Evaluate(new ExpiredAccountRule(), context).Count > 0);
    }

    [Fact]
    public void ExpiredAccountRuleSkipsMissingExpiration()
    {
        Assert.Empty(Evaluate(new ExpiredAccountRule(), Context(user: User(accountExpires: null))));
    }

    [Fact]
    public void LockedAccountRuleUsesComputedLockoutFlagAndIgnoresHistoricalLockoutTime()
    {
        Assert.Single(Evaluate(new LockedAccountRule(), Context(user: User(computedUac: 0x10))));
        Assert.Empty(Evaluate(new LockedAccountRule(), Context(user: User(computedUac: 0))));
        Assert.Empty(Evaluate(new LockedAccountRule(), Context(user: User(computedUac: null, lockoutTimeRaw: 123))));
    }

    [Fact]
    public void PasswordNeverExpiresRuleChecksUacFlag()
    {
        Assert.Single(Evaluate(new PasswordNeverExpiresRule(), Context(user: User(
            uac: (long)UserAccountControlFlags.DontExpirePassword))));
        Assert.Empty(Evaluate(new PasswordNeverExpiresRule(), Context()));
    }

    [Theory]
    [InlineData(179, false)]
    [InlineData(180, true)]
    [InlineData(181, true)]
    public void OldPasswordRuleUsesInclusiveConfiguredThreshold(int passwordAgeDays, bool expected)
    {
        var context = Context(user: User(passwordLastSet: Now.AddDays(-passwordAgeDays)));

        Assert.Equal(expected, Evaluate(new OldPasswordRule(), context).Count > 0);
    }

    [Fact]
    public void OldPasswordRuleSkipsMissingPasswordDate()
    {
        Assert.Empty(Evaluate(new OldPasswordRule(), Context(user: User(passwordLastSet: null))));
    }

    [Fact]
    public void ServiceNeverExpiresRuleRequiresBothSignalsAndDisclosesHeuristic()
    {
        var heuristic = new ServiceAccountClassification
        {
            IsServiceAccount = true,
            DetectionMethod = ServiceAccountDetectionMethod.NameHeuristic,
            Confidence = ServiceAccountDetectionConfidence.Heuristic,
            Evidence = ["Account name matches configured pattern: svc_*"]
        };
        var context = Context(
            user: User(uac: (long)UserAccountControlFlags.DontExpirePassword),
            serviceAccount: heuristic);

        var finding = Assert.Single(Evaluate(new ServicePasswordNeverExpiresRule(), context));
        Assert.Contains("DONT_EXPIRE_PASSWORD", finding.Evidence, StringComparison.Ordinal);
        Assert.Contains("heuristic", finding.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Evaluate(new ServicePasswordNeverExpiresRule(), Context(
            user: User(uac: (long)UserAccountControlFlags.DontExpirePassword))));
        Assert.Empty(Evaluate(new ServicePasswordNeverExpiresRule(), Context(
            serviceAccount: new ServiceAccountClassification { IsServiceAccount = true })));
    }

    [Fact]
    public void DirectPrivilegeRuleCreatesOneFindingPerDistinctDirectTarget()
    {
        var first = Membership("Domain Admins", direct: true, depth: 1, path: ["ivan", "Domain Admins"]);
        var duplicate = first;
        var nested = Membership("Backup Operators", direct: false, depth: 2, path: ["ivan", "Ops", "Backup Operators"]);

        var findings = Evaluate(new DirectPrivilegedMembershipRule(), Context(privilegedMemberships: [first, duplicate, nested]));

        var finding = Assert.Single(findings);
        Assert.Equal(RiskRuleIds.DirectPrivilegedMembership, finding.RuleId);
        Assert.Contains("ivan → Domain Admins", finding.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("Backup Operators", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void DirectPrivilegeRulePreservesSeparateDirectTargets()
    {
        var memberships = new[]
        {
            Membership("Domain Admins", direct: true, depth: 1, path: ["ivan", "Domain Admins"]),
            Membership("Backup Operators", direct: true, depth: 1, path: ["ivan", "Backup Operators"])
        };

        var findings = Evaluate(new DirectPrivilegedMembershipRule(), Context(privilegedMemberships: memberships));

        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, finding => finding.Evidence?.Contains("Domain Admins", StringComparison.Ordinal) == true);
        Assert.Contains(findings, finding => finding.Evidence?.Contains("Backup Operators", StringComparison.Ordinal) == true);
    }

    [Fact]
    public void NestedPrivilegeRuleIncludesFullPathAndSkipsDirectMembership()
    {
        var nested = Membership("Domain Admins", direct: false, depth: 3, path: ["ivan", "HelpDesk", "IT Administrators", "Domain Admins"]);
        var direct = Membership("Backup Operators", direct: true, depth: 1, path: ["ivan", "Backup Operators"]);

        var finding = Assert.Single(Evaluate(new NestedPrivilegedMembershipRule(), Context(privilegedMemberships: [nested, direct])));
        Assert.Contains("ivan → HelpDesk → IT Administrators → Domain Admins", finding.Evidence, StringComparison.Ordinal);
        Assert.Contains("depth: 3", finding.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(30, finding.RiskPoints);
        Assert.Equal(RiskSeverity.High, finding.Severity);
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(3, true)]
    public void MultiplePrivilegeRuleCountsDistinctTargets(int count, bool expected)
    {
        var memberships = Enumerable.Range(0, count)
            .Select(index => Membership($"Group {index}", direct: index % 2 == 0, depth: 1, path: ["ivan", $"Group {index}"]))
            .ToList();
        memberships.Add(memberships[0]);

        Assert.Equal(expected, Evaluate(new MultipleAdministrativeRolesRule(), Context(privilegedMemberships: memberships)).Count > 0);
    }

    [Theory]
    [InlineData(29, false)]
    [InlineData(30, true)]
    [InlineData(31, true)]
    public void InactivePrivilegedRuleUsesItsOwnThreshold(int days, bool expected)
    {
        var context = Context(
            user: User(lastActivity: Now.AddDays(-days)),
            privilegedMemberships: [Membership("Domain Admins", direct: true, depth: 1, path: ["ivan", "Domain Admins"])]);

        Assert.Equal(expected, Evaluate(new InactivePrivilegedAccountRule(), context).Count > 0);
    }

    [Fact]
    public void InactivePrivilegedRuleSkipsDisabledOrUnobservedAccounts()
    {
        var membership = Membership("Domain Admins", direct: true, depth: 1, path: ["ivan", "Domain Admins"]);
        Assert.Empty(Evaluate(new InactivePrivilegedAccountRule(), Context(
            user: User(uac: (long)UserAccountControlFlags.AccountDisable, lastActivity: Now.AddDays(-365)),
            privilegedMemberships: [membership])));
        Assert.Empty(Evaluate(new InactivePrivilegedAccountRule(), Context(
            user: User(lastActivity: null), privilegedMemberships: [membership])));
        Assert.Empty(Evaluate(new InactivePrivilegedAccountRule(), Context(user: User(lastActivity: Now.AddDays(-365)))));
    }

    [Theory]
    [InlineData(DelegationType.Unconstrained, RiskRuleIds.UnconstrainedDelegation)]
    [InlineData(DelegationType.Constrained, RiskRuleIds.ConstrainedDelegation)]
    [InlineData(DelegationType.ProtocolTransition, RiskRuleIds.ProtocolTransition)]
    [InlineData(DelegationType.ResourceBasedConstrained, RiskRuleIds.ResourceBasedConstrainedDelegation)]
    public void DelegationRulesUseAnalyzerResults(DelegationType type, string ruleId)
    {
        var user = User();
        var delegation = new DelegationAnalysisResult
        {
            ObjectGuid = user.ObjectGuid,
            ObjectName = "ivan",
            DelegationType = type,
            Targets = type is DelegationType.Constrained or DelegationType.ProtocolTransition ? ["HTTP/app01"] : [],
            Evidence = $"Configured {type} mechanism.",
            RequiresDetailedReview = type == DelegationType.ResourceBasedConstrained
        };
        var rule = CreateRules().Single(candidate => candidate.RuleId == ruleId);

        var finding = Assert.Single(Evaluate(rule, Context(user: user, delegations: [delegation])));
        Assert.Equal(ruleId, finding.RuleId);
        Assert.Contains("Configured", finding.Evidence, StringComparison.Ordinal);
        if (delegation.Targets.Count > 0)
        {
            Assert.Contains("HTTP/app01", finding.Evidence, StringComparison.OrdinalIgnoreCase);
        }
        if (type == DelegationType.ResourceBasedConstrained)
        {
            Assert.Contains("ACL", finding.Description, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("ACL", finding.Recommendation, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void DelegationRulesDoNotReclassifyOrAcceptAnotherAccountsResult()
    {
        var user = User();
        var other = new DelegationAnalysisResult
        {
            ObjectGuid = Guid.NewGuid(),
            DelegationType = DelegationType.Constrained,
            Evidence = "Another account's delegation."
        };
        Assert.Empty(Evaluate(new ConstrainedDelegationRule(), Context(user: user, delegations: [other])));
        Assert.Empty(Evaluate(new ConstrainedDelegationRule(), Context(user: user, delegations:
        [
            new DelegationAnalysisResult { ObjectGuid = user.ObjectGuid, DelegationType = DelegationType.ProtocolTransition }
        ])));
    }

    [Fact]
    public void EachDelegationRuleIgnoresOtherDelegationTypes()
    {
        var user = User();
        var results = Enum.GetValues<DelegationType>()
            .Where(type => type != DelegationType.None)
            .Select(type => new DelegationAnalysisResult
            {
                ObjectGuid = user.ObjectGuid,
                DelegationType = type,
                Evidence = $"{type} evidence"
            })
            .ToArray();

        Assert.Empty(Evaluate(new UnconstrainedDelegationRule(), Context(user: user, delegations: results.Where(item => item.DelegationType != DelegationType.Unconstrained).ToArray())));
        Assert.Empty(Evaluate(new ConstrainedDelegationRule(), Context(user: user, delegations: results.Where(item => item.DelegationType != DelegationType.Constrained).ToArray())));
        Assert.Empty(Evaluate(new ProtocolTransitionRule(), Context(user: user, delegations: results.Where(item => item.DelegationType != DelegationType.ProtocolTransition).ToArray())));
        Assert.Empty(Evaluate(new ResourceBasedConstrainedDelegationRule(), Context(user: user, delegations: results.Where(item => item.DelegationType != DelegationType.ResourceBasedConstrained).ToArray())));
    }

    [Fact]
    public void SidHistoryRuleReportsValuesAndBoundsLongEvidence()
    {
        Assert.Empty(Evaluate(new SidHistoryRule(), Context(user: User(sidHistory: []))));
        var finding = Assert.Single(Evaluate(new SidHistoryRule(), Context(user: User(sidHistory:
            Enumerable.Range(0, 12).Select(index => $"S-1-5-21-{index}").ToArray()))));
        Assert.Contains("SIDHistory count: 12", finding.Evidence, StringComparison.Ordinal);
        Assert.Contains("Additional values omitted: 2", finding.Evidence, StringComparison.Ordinal);
        Assert.Contains("S-1-5-21-0", finding.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("S-1-5-21-11", finding.Evidence, StringComparison.Ordinal);
        var oneValue = Assert.Single(Evaluate(new SidHistoryRule(), Context(user: User(sidHistory: ["S-1-5-21-42"]))));
        Assert.Contains("SIDHistory count: 1", oneValue.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void DuplicateSpnAnalyzerGroupsAcrossDistinctObjectsAndIgnoresLocalDuplicates()
    {
        var first = User(name: "first", spns: ["HTTP/App01", "HTTP/App01", " "]);
        var second = User(name: "second", spns: ["http/app01"]);
        var single = User(name: "single", spns: ["HTTP/only"]);
        var localDuplicate = User(name: "local-only", spns: ["HTTP/local", "http/local"]);
        var analyzer = new DuplicateSpnAnalyzer();

        var result = analyzer.AnalyzeAll([first, second, single, localDuplicate]);

        Assert.Equal(2, result.Count);
        var firstEvidence = Assert.Single(result[first.ObjectGuid]);
        Assert.Equal("HTTP/App01", firstEvidence.ServicePrincipalName);
        Assert.Equal(["second"], firstEvidence.OtherObjectNames);
        Assert.False(result.ContainsKey(single.ObjectGuid));
        Assert.False(result.ContainsKey(localDuplicate.ObjectGuid));
    }

    [Fact]
    public void DuplicateSpnRuleProducesFindingForEachAffectedObjectAndDeduplicatesContext()
    {
        var user = User(name: "first", spns: ["HTTP/app01"]);
        var duplicate = new DuplicateSpnEvidence
        {
            ObjectGuid = user.ObjectGuid,
            ObjectName = "first",
            ServicePrincipalName = "HTTP/app01",
            OtherObjectNames = ["second"]
        };
        var context = Context(user: user, duplicateSpns: [duplicate, duplicate]);

        var finding = Assert.Single(Evaluate(new DuplicateSpnRule(), context));
        Assert.Contains("Duplicate SPN: HTTP/app01", finding.Evidence, StringComparison.Ordinal);
        Assert.Contains("Also assigned to: second", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void RiskEngineRunsAllRulesAndReturnsDistinctFindings()
    {
        var user = User(uac: (long)UserAccountControlFlags.DontExpirePassword, lastActivity: Now.AddDays(-90));
        var context = Context(
            user: user,
            privilegedMemberships: [Membership("Domain Admins", direct: false, depth: 2, path: ["ivan", "IT", "Domain Admins"])]);
        var engine = new RiskEngine(CreateRules(), NullLogger<RiskEngine>.Instance);

        var findings = engine.Evaluate(context);

        Assert.Contains(findings, finding => finding.RuleId == RiskRuleIds.StaleEnabledAccount);
        Assert.Contains(findings, finding => finding.RuleId == RiskRuleIds.PasswordNeverExpires);
        Assert.Contains(findings, finding => finding.RuleId == RiskRuleIds.NestedPrivilegedMembership);
        Assert.All(findings, finding =>
        {
            Assert.False(string.IsNullOrWhiteSpace(finding.RuleId));
            Assert.False(string.IsNullOrWhiteSpace(finding.Category));
            Assert.False(string.IsNullOrWhiteSpace(finding.Title));
            Assert.False(string.IsNullOrWhiteSpace(finding.Description));
            Assert.False(string.IsNullOrWhiteSpace(finding.Evidence));
            Assert.False(string.IsNullOrWhiteSpace(finding.Recommendation));
        });
    }

    [Fact]
    public void RiskEngineReturnsNoFindingsForOrdinaryCurrentAccount()
    {
        var user = User(
            lastActivity: Now.AddDays(-1),
            passwordLastSet: Now.AddDays(-1),
            spns: ["HTTP/unique"]);
        var context = Context(user: user, serviceAccount: new ServiceAccountClassification());

        Assert.Empty(new RiskEngine(CreateRules(), NullLogger<RiskEngine>.Instance).Evaluate(context));
    }

    [Fact]
    public void RiskEngineHandlesNullHeavyOptionalData()
    {
        var user = User(
            name: null,
            lastActivity: null,
            passwordLastSet: null,
            accountExpires: null,
            computedUac: null,
            sidHistory: [],
            spns: []);
        var context = Context(user: user);

        Assert.Empty(new RiskEngine(CreateRules(), NullLogger<RiskEngine>.Instance).Evaluate(context));
    }

    [Fact]
    public void RiskEngineContinuesAfterAnIndividualRuleThrows()
    {
        var engine = new RiskEngine(
            [new ThrowingRule(), new PasswordNeverExpiresRule()],
            NullLogger<RiskEngine>.Instance);
        var context = Context(user: User(uac: (long)UserAccountControlFlags.DontExpirePassword));

        var finding = Assert.Single(engine.Evaluate(context));

        Assert.Equal(RiskRuleIds.PasswordNeverExpires, finding.RuleId);
    }

    [Fact]
    public void RuleIdsAreUniqueAndMatchConfiguredCatalog()
    {
        var rules = CreateRules();

        Assert.Equal(RiskRuleIds.All.Count - 2, rules.Count);
        Assert.Equal(rules.Count, rules.Select(rule => rule.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(
            RiskRuleIds.All.Where(ruleId => ruleId is not (RiskRuleIds.PossiblePasswordSpray or RiskRuleIds.PossibleBruteForce))
                .OrderBy(ruleId => ruleId, StringComparer.Ordinal),
            rules.Select(rule => rule.RuleId).OrderBy(ruleId => ruleId, StringComparer.Ordinal));
        Assert.Equal(RiskRuleIds.All.Count, RiskRuleIds.All.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Empty(new RiskSettings().Validate(new System.ComponentModel.DataAnnotations.ValidationContext(new RiskSettings())));
    }

    [Fact]
    public void RiskEngineRejectsDuplicateRuleIds()
    {
        Assert.Throws<ArgumentException>(() => new RiskEngine(
            [new PasswordNeverExpiresRule(), new PasswordNeverExpiresRule()],
            NullLogger<RiskEngine>.Instance));
    }

    [Fact]
    public void RuleMetadataPointsAndSeverityComeFromSettings()
    {
        var settings = new RiskSettings();
        settings.Rules[RiskRuleIds.PasswordNeverExpires] = new RiskRuleSettings
        {
            RiskPoints = 42,
            Severity = RiskSeverity.Critical
        };

        var finding = Assert.Single(Evaluate(new PasswordNeverExpiresRule(), Context(
            user: User(uac: (long)UserAccountControlFlags.DontExpirePassword),
            settings: settings)));

        Assert.Equal(42, finding.RiskPoints);
        Assert.Equal(RiskSeverity.Critical, finding.Severity);
    }

    private static IReadOnlyList<RiskFindingResult> Evaluate(IAdRiskRule rule, AdRiskEvaluationContext context) =>
        rule.Evaluate(context).ToArray();

    private static AdRiskEvaluationContext Context(
        AdUserRecord? user = null,
        IReadOnlyList<PrivilegedMembershipResult>? privilegedMemberships = null,
        IReadOnlyList<DelegationAnalysisResult>? delegations = null,
        IReadOnlyList<DuplicateSpnEvidence>? duplicateSpns = null,
        ServiceAccountClassification? serviceAccount = null,
        RiskSettings? settings = null)
    {
        user ??= User();
        return new AdRiskEvaluationContext
        {
            User = user,
            PrivilegeAnalysis = new PrivilegeAnalysisResult
            {
                UserObjectGuid = user.ObjectGuid,
                UserName = user.SamAccountName ?? "user",
                PrivilegedMemberships = privilegedMemberships ?? Array.Empty<PrivilegedMembershipResult>()
            },
            ServiceAccountClassification = serviceAccount ?? new ServiceAccountClassification { ObjectGuid = user.ObjectGuid },
            DelegationResults = delegations ?? Array.Empty<DelegationAnalysisResult>(),
            DuplicateSpns = duplicateSpns ?? Array.Empty<DuplicateSpnEvidence>(),
            CurrentUtc = Now,
            Settings = settings ?? new RiskSettings()
        };
    }

    private static AdUserRecord User(
        string? name = "ivan",
        long uac = (long)UserAccountControlFlags.NormalAccount,
        long? computedUac = null,
        long? lockoutTimeRaw = null,
        DateTimeOffset? lastActivity = null,
        DateTimeOffset? passwordLastSet = null,
        DateTimeOffset? accountExpires = null,
        IReadOnlyList<string>? sidHistory = null,
        IReadOnlyList<string>? spns = null) => new()
    {
        ObjectGuid = Guid.NewGuid(),
        DistinguishedName = $"CN={name ?? "missing"},OU=Users,DC=adlab,DC=test",
        SamAccountName = name,
        UserAccountControl = uac,
        ComputedUserAccountControl = computedUac,
        LockoutTimeRaw = lockoutTimeRaw,
        LastKnownActivityUtc = lastActivity,
        PasswordLastSetUtc = passwordLastSet,
        AccountExpiresUtc = accountExpires,
        SidHistory = sidHistory ?? [],
        ServicePrincipalNames = spns ?? []
    };

    private static PrivilegedMembershipResult Membership(string name, bool direct, int depth, IReadOnlyList<string> path) => new()
    {
        GroupObjectGuid = Guid.NewGuid(),
        GroupName = name,
        GroupDistinguishedName = $"CN={name},OU=Groups,DC=adlab,DC=test",
        IsDirect = direct,
        Depth = depth,
        PathDisplayNames = path
    };

    private static IReadOnlyList<IAdRiskRule> CreateRules() =>
    [
        new StaleEnabledAccountRule(),
        new ExpiredAccountRule(),
        new LockedAccountRule(),
        new PasswordNeverExpiresRule(),
        new OldPasswordRule(),
        new ServicePasswordNeverExpiresRule(),
        new DirectPrivilegedMembershipRule(),
        new NestedPrivilegedMembershipRule(),
        new MultipleAdministrativeRolesRule(),
        new InactivePrivilegedAccountRule(),
        new UnconstrainedDelegationRule(),
        new ConstrainedDelegationRule(),
        new ProtocolTransitionRule(),
        new ResourceBasedConstrainedDelegationRule(),
        new SidHistoryRule(),
        new DuplicateSpnRule()
    ];

    private sealed class ThrowingRule : IAdRiskRule
    {
        public string RuleId => "IRA-TEST-THROW";
        public string Category => "Test";
        public IEnumerable<RiskFindingResult> Evaluate(AdRiskEvaluationContext context) => throw new InvalidOperationException("Test rule failure.");
    }
}
