using System.ComponentModel.DataAnnotations;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.Scoring;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Tests;

public sealed class RiskScoringServiceTests
{
    [Fact]
    public void SumsDistinctFindingPointsAndUsesScoreThresholdsInsteadOfFindingSeverity()
    {
        var objectId = Guid.NewGuid();
        var findings = new[]
        {
            Finding(objectId, "IRA-ACCOUNT-001", 15, RiskSeverity.Low, "stale"),
            Finding(objectId, "IRA-PRIV-002", 30, RiskSeverity.Medium, "nested")
        };

        var result = Service().ScoreObject(objectId, "ivan", findings);

        Assert.Equal(45, result.RawScore);
        Assert.Equal(45, result.RiskScore);
        Assert.Equal(RiskSeverity.Medium, result.RiskLevel);
        Assert.Equal(2, result.FindingsCount);
    }

    [Fact]
    public void CapsScoreAtOneHundredButPreservesRawScore()
    {
        var objectId = Guid.NewGuid();
        var result = Service().ScoreObject(objectId, "ivan",
        [
            Finding(objectId, "IRA-DELEGATION-001", 50, RiskSeverity.Critical, "unconstrained"),
            Finding(objectId, "IRA-DELEGATION-003", 35, RiskSeverity.High, "protocol transition"),
            Finding(objectId, "IRA-PRIV-001", 30, RiskSeverity.High, "privileged")
        ]);

        Assert.Equal(115, result.RawScore);
        Assert.Equal(100, result.RiskScore);
        Assert.Equal(RiskSeverity.Critical, result.RiskLevel);
    }

    [Fact]
    public void EmptyFindingsProduceZeroLowRiskResult()
    {
        var result = Service().ScoreObject(Guid.NewGuid(), "clean-user", []);

        Assert.Equal(0, result.RawScore);
        Assert.Equal(0, result.RiskScore);
        Assert.Equal(RiskSeverity.Low, result.RiskLevel);
        Assert.Equal(0, result.FindingsCount);
    }

    [Theory]
    [InlineData(0, RiskSeverity.Low)]
    [InlineData(24, RiskSeverity.Low)]
    [InlineData(25, RiskSeverity.Medium)]
    [InlineData(49, RiskSeverity.Medium)]
    [InlineData(50, RiskSeverity.High)]
    [InlineData(74, RiskSeverity.High)]
    [InlineData(75, RiskSeverity.Critical)]
    [InlineData(100, RiskSeverity.Critical)]
    public void UsesInclusiveDefaultRiskLevelBoundaries(int score, RiskSeverity expectedLevel)
    {
        var objectId = Guid.NewGuid();
        var result = Service().ScoreObject(objectId, "user", [Finding(objectId, "IRA-TEST", score, RiskSeverity.Low, $"score-{score}")]);

        Assert.Equal(expectedLevel, result.RiskLevel);
    }

    [Fact]
    public void UsesCustomRiskLevelThresholds()
    {
        var settings = new RiskSettings { MediumFrom = 20, HighFrom = 40, CriticalFrom = 80 };
        var scoring = Service(settings);

        Assert.Equal(RiskSeverity.Low, Score(scoring, 19).RiskLevel);
        Assert.Equal(RiskSeverity.Medium, Score(scoring, 20).RiskLevel);
        Assert.Equal(RiskSeverity.High, Score(scoring, 40).RiskLevel);
        Assert.Equal(RiskSeverity.Critical, Score(scoring, 80).RiskLevel);
    }

    [Theory]
    [InlineData(50, 40, 75)]
    [InlineData(25, 50, 101)]
    [InlineData(-1, 50, 75)]
    [InlineData(25, 25, 75)]
    public void RejectsInvalidScoringThresholds(int medium, int high, int critical)
    {
        var settings = new RiskSettings { MediumFrom = medium, HighFrom = high, CriticalFrom = critical };

        Assert.NotEmpty(settings.Validate(new ValidationContext(settings)));
    }

    [Fact]
    public void DeduplicatesIdenticalFindingsButKeepsSameRuleForDifferentTargets()
    {
        var objectId = Guid.NewGuid();
        var domainAdmins = Finding(objectId, "IRA-PRIV-001", 30, RiskSeverity.High, "Path: ivan -> Domain Admins");
        var backupOperators = Finding(objectId, "IRA-PRIV-001", 30, RiskSeverity.High, "Path: ivan -> Backup Operators");

        var result = Service().ScoreObject(objectId, "ivan", [domainAdmins, domainAdmins, backupOperators]);

        Assert.Equal(60, result.RawScore);
        Assert.Equal(2, result.FindingsCount);
    }

    [Fact]
    public void NegativeFindingPointsCannotReduceRisk()
    {
        var objectId = Guid.NewGuid();
        var result = Service().ScoreObject(objectId, "user",
        [
            Finding(objectId, "IRA-TEST-NEGATIVE", -20, RiskSeverity.High, "negative malformed input"),
            Finding(objectId, "IRA-TEST-VALID", 15, RiskSeverity.Low, "valid")
        ]);

        Assert.Equal(15, result.RawScore);
        Assert.Equal(15, result.RiskScore);
        Assert.Equal(2, result.FindingsCount);
    }

    [Fact]
    public void IgnoresFindingsForOtherObjectsWhenScoringOneObject()
    {
        var objectId = Guid.NewGuid();

        var result = Service().ScoreObject(objectId, "user",
        [
            Finding(objectId, "IRA-TEST", 15, RiskSeverity.Low, "this object"),
            Finding(Guid.NewGuid(), "IRA-TEST", 90, RiskSeverity.Critical, "other object")
        ]);

        Assert.Equal(15, result.RawScore);
        Assert.Single(result.Findings);
    }

    [Fact]
    public void ScoreObjectsIncludesCleanObjectsAndFindingsWithoutExplicitObjectInput()
    {
        var cleanId = Guid.NewGuid();
        var affectedId = Guid.NewGuid();

        var results = Service().ScoreObjects(
        [new RiskScoringObject { ObjectGuid = cleanId, ObjectName = "clean" }],
        [Finding(affectedId, "IRA-TEST", 15, RiskSeverity.Medium, "evidence", objectName: "affected")]);

        Assert.Equal(2, results.Count);
        Assert.Equal(0, Assert.Single(results, item => item.ObjectGuid == cleanId).RiskScore);
        Assert.Equal(15, Assert.Single(results, item => item.ObjectGuid == affectedId).RiskScore);
    }

    [Fact]
    public void ComputesAdSecurityScoreFromAverageObjectRisk()
    {
        var objects = new[]
        {
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "A" },
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "B" },
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "C" }
        };
        var findings = new[]
        {
            Finding(objects[0].ObjectGuid, "IRA-TEST-A", 20, RiskSeverity.Low, "A"),
            Finding(objects[1].ObjectGuid, "IRA-TEST-B", 60, RiskSeverity.High, "B"),
            Finding(objects[2].ObjectGuid, "IRA-TEST-C", 10, RiskSeverity.Low, "C")
        };

        var result = Service().ScoreAll(objects, findings);

        Assert.Equal(70, result.SecurityScore);
        Assert.Equal(3, result.AnalysedObjects);
        Assert.Equal(30, result.AverageRiskScore);
    }

    [Fact]
    public void RoundsAdSecurityScoreToNearestIntegerAwayFromZero()
    {
        var objects = new[]
        {
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "A" },
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "B" }
        };
        var findings = new[]
        {
            Finding(objects[0].ObjectGuid, "IRA-A", 99, RiskSeverity.Critical, "A"),
            Finding(objects[1].ObjectGuid, "IRA-B", 100, RiskSeverity.Critical, "B")
        };

        var result = Service().ScoreAll(objects, findings);

        Assert.Equal(99.5, result.AverageRiskScore);
        Assert.Equal(1, result.SecurityScore);
    }

    [Fact]
    public void CleanDirectoryScoresOneHundredAndNoObjectsReturnNoData()
    {
        var cleanObjects = Enumerable.Range(0, 3)
            .Select(index => new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = $"clean-{index}" })
            .ToArray();
        var cleanResult = Service().ScoreAll(cleanObjects, []);
        var emptyResult = Service().ScoreAll([], []);

        Assert.Equal(100, cleanResult.SecurityScore);
        Assert.Equal(0, cleanResult.TotalFindings);
        Assert.Null(emptyResult.SecurityScore);
        Assert.Equal(0, emptyResult.AnalysedObjects);
        Assert.Null(emptyResult.AverageRiskScore);
    }

    [Fact]
    public void AllCriticalObjectsProduceZeroAdSecurityScore()
    {
        var objects = new[]
        {
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "critical-A" },
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "critical-B" }
        };
        var findings = objects.Select(item => Finding(item.ObjectGuid, "IRA-CRIT", 100, RiskSeverity.Critical, item.ObjectName)).ToArray();

        var result = Service().ScoreAll(objects, findings);

        Assert.Equal(0, result.SecurityScore);
        Assert.Equal(2, result.CriticalObjects);
        Assert.Equal(2, result.CriticalFindings);
    }

    [Fact]
    public void SummaryCountsObjectsAndFindingSeveritiesSeparately()
    {
        var objects = new[]
        {
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "low" },
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "medium" },
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "high" },
            new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "critical" }
        };
        var findings = new[]
        {
            Finding(objects[0].ObjectGuid, "IRA-LOW", 10, RiskSeverity.Critical, "critical finding on low-score object"),
            Finding(objects[1].ObjectGuid, "IRA-MEDIUM", 30, RiskSeverity.Low, "low-severity finding"),
            Finding(objects[2].ObjectGuid, "IRA-HIGH", 60, RiskSeverity.Medium, "medium-severity finding"),
            Finding(objects[3].ObjectGuid, "IRA-CRITICAL", 90, RiskSeverity.High, "high-severity finding")
        };

        var result = Service().ScoreAll(objects, findings);

        Assert.Equal(1, result.LowRiskObjects);
        Assert.Equal(1, result.MediumRiskObjects);
        Assert.Equal(1, result.HighRiskObjects);
        Assert.Equal(1, result.CriticalObjects);
        Assert.Equal(1, result.CriticalFindings);
        Assert.Equal(1, result.LowFindings);
        Assert.Equal(1, result.MediumFindings);
        Assert.Equal(1, result.HighFindings);
    }

    [Fact]
    public void AggregatesCategoryFindingsAndDistinctAffectedObjects()
    {
        var firstId = Guid.NewGuid();
        var secondId = Guid.NewGuid();
        var findings = new[]
        {
            Finding(firstId, "IRA-PRIV-001", 30, RiskSeverity.High, "Domain Admins", category: "Privilege"),
            Finding(firstId, "IRA-PRIV-002", 30, RiskSeverity.High, "Nested path", category: "Privilege"),
            Finding(secondId, "IRA-PRIV-001", 30, RiskSeverity.High, "Backup Operators", category: "Privilege"),
            Finding(secondId, "IRA-PASSWORD-001", 15, RiskSeverity.Medium, "Never expires", category: "Password"),
            Finding(secondId, "IRA-DEL-001", 20, RiskSeverity.Medium, "Delegation", category: "Delegation")
        };
        var objects = new[]
        {
            new RiskScoringObject { ObjectGuid = firstId, ObjectName = "A" },
            new RiskScoringObject { ObjectGuid = secondId, ObjectName = "B" }
        };

        var summaries = Service().ScoreAll(objects, findings).CategorySummaries;

        var privilege = Assert.Single(summaries, summary => summary.Category == "Privilege");
        Assert.Equal(3, privilege.FindingsCount);
        Assert.Equal(2, privilege.AffectedObjects);
        Assert.Equal(1, Assert.Single(summaries, summary => summary.Category == "Password").FindingsCount);
        Assert.Equal(1, Assert.Single(summaries, summary => summary.Category == "Delegation").FindingsCount);
    }

    [Fact]
    public void TopRiskyObjectsUseScoreSeverityFindingCountAndStableNameOrdering()
    {
        var criticalA = new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "Critical A" };
        var criticalB = new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "Critical B" };
        var highZ = new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "High Z" };
        var highA = new RiskScoringObject { ObjectGuid = Guid.NewGuid(), ObjectName = "High A" };
        var objects = new[] { highZ, criticalB, highA, criticalA };
        var findings = new[]
        {
            Finding(criticalA.ObjectGuid, "IRA-C1", 40, RiskSeverity.Critical, "C1"),
            Finding(criticalA.ObjectGuid, "IRA-C2", 40, RiskSeverity.High, "C2"),
            Finding(criticalB.ObjectGuid, "IRA-C3", 40, RiskSeverity.Critical, "C3"),
            Finding(criticalB.ObjectGuid, "IRA-C4", 40, RiskSeverity.Critical, "C4"),
            Finding(highZ.ObjectGuid, "IRA-H1", 80, RiskSeverity.High, "HZ"),
            Finding(highZ.ObjectGuid, "IRA-H2", 0, RiskSeverity.Low, "HZ-extra"),
            Finding(highA.ObjectGuid, "IRA-H2", 80, RiskSeverity.High, "HA")
        };

        var result = Service().ScoreAll(objects, findings, topRiskyObjectsCount: 4);

        Assert.Equal(["Critical B", "Critical A", "High Z", "High A"], result.TopRiskyObjects.Select(item => item.ObjectName));
        Assert.Equal(3, Service().ScoreAll(objects, findings, topRiskyObjectsCount: 3).TopRiskyObjects.Count);
    }

    [Fact]
    public void LargeFindingSetDoesNotOverflowAndClampsScore()
    {
        var objectId = Guid.NewGuid();
        var findings = Enumerable.Range(0, 10_000)
            .Select(index => Finding(objectId, $"IRA-LARGE-{index}", int.MaxValue, RiskSeverity.Low, $"finding-{index}"));

        var result = Service().ScoreObject(objectId, "large", findings);

        Assert.Equal(int.MaxValue, result.RawScore);
        Assert.Equal(100, result.RiskScore);
        Assert.Equal(10_000, result.FindingsCount);
    }

    private static ObjectRiskScoreResult Score(RiskScoringService service, int points)
    {
        var objectId = Guid.NewGuid();
        return service.ScoreObject(objectId, "user", [Finding(objectId, "IRA-TEST", points, RiskSeverity.Low, $"score-{points}")]);
    }

    private static RiskScoringService Service(RiskSettings? settings = null) => new(
        Options.Create(settings ?? new RiskSettings()),
        NullLogger<RiskScoringService>.Instance);

    private static RiskFindingResult Finding(
        Guid objectGuid,
        string ruleId,
        int riskPoints,
        RiskSeverity severity,
        string evidence,
        string category = "Test",
        string? objectName = null) => new()
    {
        ObjectGuid = objectGuid,
        ObjectName = objectName ?? objectGuid.ToString("D"),
        RuleId = ruleId,
        Category = category,
        Title = ruleId,
        Description = ruleId,
        Evidence = evidence,
        Recommendation = "Review this finding.",
        RiskPoints = riskPoints,
        Severity = severity
    };
}
