using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.RiskRules;
using IdentityRiskAnalyzer.Web.Services.SecurityEvents;
using IdentityRiskAnalyzer.Web.Services.Exchange;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Tests;

public sealed class SecurityEventAnalysisTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 2, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void SecurityEventConfigurationDefaultsToOffAndValidatesThresholds()
    {
        var settings = new SecurityEventLogOptions();
        Assert.False(settings.Enabled);
        Assert.Empty(settings.Validate(new System.ComponentModel.DataAnnotations.ValidationContext(settings)));
        settings.MaximumEvents = 0;
        Assert.NotEmpty(settings.Validate(new System.ComponentModel.DataAnnotations.ValidationContext(settings)));
    }

    [Fact]
    public void ExchangeContractReportsUnavailableWithoutFabricatingRecords()
    {
        var disabled = new UnavailableExchangeDelegationCollector(Options.Create(new ExchangeDelegationOptions()));
        Assert.False(disabled.Collect(default).Enabled);
        var enabled = new UnavailableExchangeDelegationCollector(Options.Create(new ExchangeDelegationOptions { Enabled = true }));
        var result = enabled.Collect(default);
        Assert.True(result.Enabled);
        Assert.False(result.Available);
        Assert.Empty(result.Records);
    }

    [Fact]
    public void XmlParserNormalizesNamedFieldsWithoutSensitivePayload()
    {
        const string xml = "<Event><EventData><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>ADLAB</Data><Data Name='IpAddress'>10.0.0.2</Data><Data Name='Status'>0xC000006D</Data></EventData></Event>";
        var result = SecurityEventXmlParser.Parse(4625, Start.ToOffset(TimeSpan.FromHours(5)), 17, xml);
        Assert.Equal(Start, result.TimestampUtc);
        Assert.Equal("alice", result.TargetUserName);
        Assert.Equal("10.0.0.2", result.SourceIpAddress);
        Assert.Equal(17, result.RecordId);
        Assert.True(result.IsFailedAuthentication);
    }

    [Theory]
    [InlineData(4771, true)]
    [InlineData(4776, true)]
    [InlineData(4740, false)]
    public void AdditionalEventIdsNormalizeWithoutBecomingWrongThreatType(int eventId, bool isFailure)
    {
        const string xml = "<Event><EventData><Data Name='TargetUserName'>alice</Data><Data Name='Workstation'>CLIENT01</Data></EventData></Event>";
        var result = SecurityEventXmlParser.Parse(eventId, Start, 1, xml);
        Assert.Equal("alice", result.TargetUserName);
        Assert.Equal("CLIENT01", result.WorkstationName);
        Assert.Equal(isFailure, result.IsFailedAuthentication);
    }

    [Fact]
    public void SprayRequiresSourceFailuresAndDistinctUsersWithinWindow()
    {
        var analyzer = new AuthenticationThreatAnalyzer(Options.Create(new SecurityEventLogOptions()));
        var events = Enumerable.Range(0, 10).Select(index => Event(index, $"user{index % 5}", "10.0.0.2")).ToArray();
        var threat = Assert.Single(analyzer.Analyze(events));
        Assert.Equal(AuthenticationThreatType.PossiblePasswordSpray, threat.Type);
        Assert.Equal(10, threat.FailedAttempts);
        Assert.Equal(5, threat.AffectedUserNames.Count);
        Assert.Empty(analyzer.Analyze(events.Select(item => new SecurityAuthenticationEvent
        {
            EventId = item.EventId, RecordId = item.RecordId, TimestampUtc = item.TimestampUtc,
            TargetUserName = item.TargetUserName
        }).ToArray()));
    }

    [Fact]
    public void BruteForceCorrelatesCaseInsensitiveUsernamesAcrossSources()
    {
        var analyzer = new AuthenticationThreatAnalyzer(Options.Create(new SecurityEventLogOptions()));
        var events = Enumerable.Range(0, 10).Select(index => Event(index, index % 2 == 0 ? "ADLAB\\Alice" : "alice", $"10.0.0.{index}")).ToArray();
        var threat = Assert.Single(analyzer.Analyze(events));
        Assert.Equal(AuthenticationThreatType.PossibleBruteForce, threat.Type);
        Assert.Equal("Alice", threat.AffectedUserNames[0], ignoreCase: true);
        Assert.Null(threat.Source);
    }

    [Fact]
    public void SprayBelowUserOrFailureThresholdDoesNotTrigger()
    {
        var analyzer = new AuthenticationThreatAnalyzer(Options.Create(new SecurityEventLogOptions()));
        Assert.Empty(analyzer.Analyze(Enumerable.Range(0, 9)
            .Select(index => Event(index, $"user{index % 5}", "10.0.0.2")).ToArray()));
        Assert.Empty(analyzer.Analyze(Enumerable.Range(0, 10)
            .Select(index => Event(index, $"user{index % 4}", "10.0.0.2")).ToArray()));
    }

    [Fact]
    public void MaximumEventsBoundsAnalyzerInput()
    {
        var settings = new SecurityEventLogOptions { MaximumEvents = 9 };
        var analyzer = new AuthenticationThreatAnalyzer(Options.Create(settings));
        Assert.Empty(analyzer.Analyze(Enumerable.Range(0, 10).Select(index => Event(index, "alice", "10.0.0.2")).ToArray()));
    }

    [Fact]
    public void OldOrNonFailureEventsDoNotTriggerCorrelation()
    {
        var analyzer = new AuthenticationThreatAnalyzer(Options.Create(new SecurityEventLogOptions()));
        var old = Enumerable.Range(0, 10).Select(index => Event(index * 11, "alice", "10.0.0.2")).ToArray();
        var lockout = Enumerable.Range(0, 10).Select(index => new SecurityAuthenticationEvent
        { EventId = 4740, TimestampUtc = Start.AddMinutes(index), TargetUserName = "alice", SourceIpAddress = "10.0.0.2" }).ToArray();
        Assert.Empty(analyzer.Analyze(old.Concat(lockout).ToArray()));
    }

    [Fact]
    public void DuplicateRecordIdsAreNotCountedTwice()
    {
        var analyzer = new AuthenticationThreatAnalyzer(Options.Create(new SecurityEventLogOptions()));
        var events = Enumerable.Range(0, 9).Select(index => Event(index, "alice", "10.0.0.2")).ToList();
        events.Add(events[0]);
        Assert.Empty(analyzer.Analyze(events));
    }

    [Fact]
    public void MapperUsesOnlyMatchedObjectGuidsAndConfiguredRiskWeight()
    {
        var known = User("alice");
        var threat = new AuthenticationThreat
        {
            Type = AuthenticationThreatType.PossiblePasswordSpray, Source = "IP 10.0.0.2",
            WindowStartUtc = Start, WindowEndUtc = Start.AddMinutes(5), FailedAttempts = 12,
            AffectedUserNames = ["ALICE", "unknown"]
        };
        var results = AuthenticationFindingMapper.Map([threat], [known], new RiskSettings());
        var finding = Assert.Single(results[known.ObjectGuid]);
        Assert.Equal(RiskRuleIds.PossiblePasswordSpray, finding.RuleId);
        Assert.Equal(RiskCategories.Authentication, finding.Category);
        Assert.Equal(30, finding.RiskPoints);
        Assert.Contains("10.0.0.2", finding.Evidence);
        Assert.DoesNotContain(results.Keys, guid => guid != known.ObjectGuid);
    }

    [Fact]
    public void AmbiguousSamNameDoesNotCreateFinding()
    {
        var threat = new AuthenticationThreat
        {
            Type = AuthenticationThreatType.PossibleBruteForce, WindowStartUtc = Start, WindowEndUtc = Start,
            FailedAttempts = 10, AffectedUserNames = ["alice"]
        };
        Assert.Empty(AuthenticationFindingMapper.Map([threat], [User("alice"), User("ALICE")], new RiskSettings()));
    }

    private static SecurityAuthenticationEvent Event(int minute, string user, string source) => new()
    {
        EventId = 4625, RecordId = minute + 1, TimestampUtc = Start.AddMinutes(minute),
        TargetUserName = user, SourceIpAddress = source
    };

    private static AdUserRecord User(string name) => new()
    {
        ObjectGuid = Guid.NewGuid(), DistinguishedName = $"CN={name},DC=adlab,DC=test", SamAccountName = name
    };
}
