using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.GroupAnalysis;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Tests;

public sealed class PrivilegedGroupAnalyzerTests
{
    [Fact]
    public void OrdinaryUserIsNotPrivileged()
    {
        var user = User("ivan");
        var domainUsers = Group("Domain Users", "CN=Domain Users,CN=Users,DC=adlab,DC=test", user.DistinguishedName);

        var result = Analyze(user, [domainUsers]);

        Assert.False(result.IsPrivileged);
        Assert.Empty(result.PrivilegedMemberships);
    }

    [Fact]
    public void DetectsDirectDomainAdminMembership()
    {
        var user = User("ivan");
        var domainAdmins = Group("Domain Admins", "CN=Domain Admins,CN=Users,DC=adlab,DC=test", user.DistinguishedName, "S-1-5-21-1-2-3-512");

        var result = Analyze(user, [domainAdmins]);
        var membership = Assert.Single(result.PrivilegedMemberships);

        Assert.True(result.IsPrivileged);
        Assert.True(membership.IsDirect);
        Assert.Equal(1, membership.Depth);
        Assert.Equal("Domain Admins", membership.GroupName);
        Assert.Equal(PrivilegedGroupMatchMethod.Rid, membership.MatchMethod);
        Assert.Equal(["ivan", "Domain Admins"], membership.PathDisplayNames);
    }

    [Fact]
    public void DetectsNestedDomainAdminMembershipAndKeepsFullPath()
    {
        var user = User("ivan");
        var helpDesk = Group("HelpDesk", "CN=HelpDesk,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);
        var itAdmins = Group("IT Administrators", "CN=IT Administrators,OU=Groups,DC=adlab,DC=test", helpDesk.DistinguishedName);
        var domainAdmins = Group("Domain Admins", "CN=Domain Admins,CN=Users,DC=adlab,DC=test", itAdmins.DistinguishedName, sid: "S-1-5-21-1-2-3-512");

        var result = Analyze(user, [domainAdmins, itAdmins, helpDesk]);
        var membership = Assert.Single(result.PrivilegedMemberships);

        Assert.True(result.IsPrivileged);
        Assert.False(membership.IsDirect);
        Assert.Equal(3, membership.Depth);
        Assert.Equal(["ivan", "HelpDesk", "IT Administrators", "Domain Admins"], membership.PathDisplayNames);
    }

    [Fact]
    public void ReturnsEveryDirectPrivilegedRole()
    {
        var user = User("ivan");
        var domainAdmins = Group("Domain Admins", "CN=Domain Admins,CN=Users,DC=adlab,DC=test", user.DistinguishedName, "S-1-5-21-1-2-3-512");
        var backupOperators = Group("Backup Operators", "CN=Backup Operators,CN=Builtin,DC=adlab,DC=test", user.DistinguishedName, "S-1-5-32-551");

        var result = Analyze(user, [domainAdmins, backupOperators]);

        Assert.True(result.IsPrivileged);
        Assert.Equal(2, result.PrivilegedGroupCount);
        Assert.All(result.PrivilegedMemberships, membership => Assert.True(membership.IsDirect));
        Assert.Contains(result.PrivilegedMemberships, membership => membership.GroupName == "Domain Admins");
        Assert.Contains(result.PrivilegedMemberships, membership => membership.GroupName == "Backup Operators");
    }

    [Fact]
    public void ReturnsDirectAndNestedPrivilegedRolesTogether()
    {
        var user = User("ivan");
        var helpDesk = Group("HelpDesk", "CN=HelpDesk,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);
        var domainAdmins = Group("Domain Admins", "CN=Domain Admins,CN=Users,DC=adlab,DC=test", helpDesk.DistinguishedName, "S-1-5-21-1-2-3-512");
        var backupOperators = Group("Backup Operators", "CN=Backup Operators,CN=Builtin,DC=adlab,DC=test", user.DistinguishedName, "S-1-5-32-551");

        var result = Analyze(user, [helpDesk, domainAdmins, backupOperators]);

        Assert.Equal(2, result.PrivilegedGroupCount);
        Assert.True(Assert.Single(result.PrivilegedMemberships, item => item.GroupName == "Backup Operators").IsDirect);
        var nested = Assert.Single(result.PrivilegedMemberships, item => item.GroupName == "Domain Admins");
        Assert.False(nested.IsDirect);
        Assert.Equal(2, nested.Depth);
    }

    [Fact]
    public void RecognizesCustomConfiguredGroup()
    {
        var user = User("ivan");
        var custom = Group("Company Tier 0 Admins", "CN=Company Tier 0 Admins,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);
        var definition = new PrivilegedGroupDefinition { Name = "Company Tier 0 Admins" };

        var result = Analyze(user, [custom], [definition]);
        var membership = Assert.Single(result.PrivilegedMemberships);

        Assert.True(result.IsPrivileged);
        Assert.Equal(PrivilegedGroupMatchMethod.ConfiguredName, membership.MatchMethod);
    }

    [Fact]
    public void DoesNotInferPrivilegeFromAdminLikeName()
    {
        var user = User("ivan");
        var custom = Group("Super Admin Team", "CN=Super Admin Team,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);

        var result = Analyze(user, [custom]);

        Assert.False(result.IsPrivileged);
        Assert.Empty(result.PrivilegedMemberships);
    }

    [Fact]
    public void ConfiguredNameFallbackIsCaseInsensitive()
    {
        var user = User("ivan");
        var group = Group("DOMAIN ADMINS", "CN=DOMAIN ADMINS,CN=Users,DC=adlab,DC=test", user.DistinguishedName);
        var definition = new PrivilegedGroupDefinition { Name = "Domain Admins" };

        var membership = Assert.Single(Analyze(user, [group], [definition]).PrivilegedMemberships);

        Assert.Equal(PrivilegedGroupMatchMethod.ConfiguredName, membership.MatchMethod);
    }

    [Fact]
    public void MatchesDomainRelativeRidWhenGroupHasBeenRenamed()
    {
        var user = User("ivan");
        var renamed = Group("Localized administration group", "CN=Localized administration group,CN=Users,DC=adlab,DC=test", user.DistinguishedName, "S-1-5-21-1-2-3-512");

        var membership = Assert.Single(Analyze(user, [renamed]).PrivilegedMemberships);

        Assert.Equal("Localized administration group", membership.GroupName);
        Assert.Equal(PrivilegedGroupMatchMethod.Rid, membership.MatchMethod);
    }

    [Fact]
    public void MatchesBuiltinSidWhenDisplayNameHasBeenLocalized()
    {
        var user = User("ivan");
        var localized = Group("Administrateurs", "CN=Administrateurs,CN=Builtin,DC=adlab,DC=test", user.DistinguishedName, "S-1-5-32-544");

        var membership = Assert.Single(Analyze(user, [localized]).PrivilegedMemberships);

        Assert.Equal(PrivilegedGroupMatchMethod.Sid, membership.MatchMethod);
    }

    [Fact]
    public void DeduplicatesWhenSidRidAndConfiguredNameMatch()
    {
        var user = User("ivan");
        var group = Group("Domain Admins", "CN=Domain Admins,CN=Users,DC=adlab,DC=test", user.DistinguishedName, "S-1-5-21-1-2-3-512");
        var definition = new PrivilegedGroupDefinition
        {
            Name = "Domain Admins",
            Sid = "S-1-5-21-1-2-3-512",
            Rid = 512
        };

        var membership = Assert.Single(Analyze(user, [group], [definition]).PrivilegedMemberships);

        Assert.Equal(PrivilegedGroupMatchMethod.Sid, membership.MatchMethod);
    }

    [Fact]
    public void DisabledConfiguredGroupIsNotClassified()
    {
        var user = User("ivan");
        var group = Group("Company Tier 0 Admins", "CN=Company Tier 0 Admins,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);
        var definition = new PrivilegedGroupDefinition { Name = "Company Tier 0 Admins", Enabled = false };

        Assert.False(Analyze(user, [group], [definition]).IsPrivileged);
    }

    [Fact]
    public void ReturnsNotPrivilegedForUserWithoutMemberships()
    {
        var user = User("ivan");

        var result = Analyze(user, []);

        Assert.False(result.IsPrivileged);
        Assert.Empty(result.PrivilegedMemberships);
    }

    [Fact]
    public void AnalyzesCycleSafeGraphPathsWithoutRunningAnotherTraversal()
    {
        var user = User("ivan");
        var groupA = Group("A", "CN=A,OU=Groups,DC=adlab,DC=test", user.DistinguishedName, "CN=C,OU=Groups,DC=adlab,DC=test");
        var groupB = Group("B", "CN=B,OU=Groups,DC=adlab,DC=test", groupA.DistinguishedName);
        var groupC = Group("C", "CN=C,OU=Groups,DC=adlab,DC=test", groupB.DistinguishedName);
        var groups = new[] { groupA, groupB, groupC };
        var paths = CreateGraphService().GetMembershipsForUser(user, [user], groups);
        var analyzer = CreateAnalyzer([new PrivilegedGroupDefinition { Name = "C" }]);

        var result = analyzer.AnalyzeUser(user, paths, groups);

        var privileged = Assert.Single(result.PrivilegedMemberships);
        Assert.Equal("C", privileged.GroupName);
        Assert.Equal(3, privileged.Depth);
    }

    [Fact]
    public void BatchAnalysisConsumesPrebuiltPathsForAllUsers()
    {
        var userA = User("ivan");
        var userB = User("maria");
        var domainAdmins = Group("Domain Admins", "CN=Domain Admins,CN=Users,DC=adlab,DC=test", userA.DistinguishedName, "S-1-5-21-1-2-3-512");
        var groups = new[] { domainAdmins };
        var users = new[] { userA, userB };
        var paths = CreateGraphService().BuildMembershipsForAllUsers(users, groups);

        var results = CreateAnalyzer().AnalyzeAllUsers(users, paths, groups);

        Assert.Equal(2, results.Count);
        Assert.True(Assert.Single(results, result => result.UserObjectGuid == userA.ObjectGuid).IsPrivileged);
        Assert.False(Assert.Single(results, result => result.UserObjectGuid == userB.ObjectGuid).IsPrivileged);
    }

    private static PrivilegeAnalysisResult Analyze(
        AdUserRecord user,
        IReadOnlyCollection<AdGroupRecord> groups,
        IReadOnlyCollection<PrivilegedGroupDefinition>? definitions = null)
    {
        var paths = CreateGraphService().GetMembershipsForUser(user, [user], groups);
        return CreateAnalyzer(definitions).AnalyzeUser(user, paths, groups);
    }

    private static PrivilegedGroupAnalyzer CreateAnalyzer(IReadOnlyCollection<PrivilegedGroupDefinition>? definitions = null)
    {
        return new PrivilegedGroupAnalyzer(
            NullLogger<PrivilegedGroupAnalyzer>.Instance,
            Options.Create(new PrivilegeAnalysisOptions
            {
                PrivilegedGroups = definitions?.ToList() ?? DefaultGroups()
            }));
    }

    private static GroupGraphService CreateGraphService() => new(
        NullLogger<GroupGraphService>.Instance,
        Options.Create(new GroupAnalysisOptions { MaxGroupNestingDepth = 64 }));

    private static List<PrivilegedGroupDefinition> DefaultGroups() =>
    [
        new() { Name = "Domain Admins", Rid = 512 },
        new() { Name = "Enterprise Admins", Rid = 519 },
        new() { Name = "Schema Admins", Rid = 518 },
        new() { Name = "Administrators", Sid = "S-1-5-32-544" },
        new() { Name = "Account Operators", Sid = "S-1-5-32-548" },
        new() { Name = "Server Operators", Sid = "S-1-5-32-549" },
        new() { Name = "Backup Operators", Sid = "S-1-5-32-551" },
        new() { Name = "DNSAdmins" }
    ];

    private static AdUserRecord User(string samAccountName) => new()
    {
        ObjectGuid = Guid.NewGuid(),
        SamAccountName = samAccountName,
        DistinguishedName = $"CN={samAccountName},OU=Users,DC=adlab,DC=test"
    };

    private static AdGroupRecord Group(string name, string dn, string memberDn, string? sid = null) => new()
    {
        ObjectGuid = Guid.NewGuid(),
        CommonName = name,
        DistinguishedName = dn,
        Sid = sid,
        MemberDistinguishedNames = [memberDn]
    };
}
