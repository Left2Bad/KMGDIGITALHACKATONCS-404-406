using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using IdentityRiskAnalyzer.Web.Services.GroupAnalysis;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Tests;

public sealed class GroupGraphServiceTests
{
    [Fact]
    public void FindsDirectMembershipWithDepthOneAndFullPath()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");
        var helpDesk = Group("HelpDesk", "CN=HelpDesk,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);

        var result = Assert.Single(CreateService().GetMembershipsForUser(user, [user], [helpDesk]));

        Assert.True(result.IsDirect);
        Assert.Equal(1, result.Depth);
        Assert.Equal(["ivan", "HelpDesk"], result.PathDisplayNames);
        Assert.Equal([user.DistinguishedName, helpDesk.DistinguishedName], result.PathDistinguishedNames);
    }

    [Fact]
    public void FindsSeveralNestedLevelsAndCountsGroupEdgesAsDepth()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");
        var groupA = Group("GroupA", "CN=GroupA,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);
        var groupB = Group("GroupB", "CN=GroupB,OU=Groups,DC=adlab,DC=test", groupA.DistinguishedName);
        var groupC = Group("GroupC", "CN=GroupC,OU=Groups,DC=adlab,DC=test", groupB.DistinguishedName);
        var groupD = Group("GroupD", "CN=GroupD,OU=Groups,DC=adlab,DC=test", groupC.DistinguishedName);

        var results = CreateService().GetMembershipsForUser(user, [user], [groupD, groupB, groupA, groupC]);

        Assert.Equal([1, 2, 3, 4], results.Select(result => result.Depth));
        var deepest = Assert.Single(results, result => result.TargetGroupName == "GroupD");
        Assert.False(deepest.IsDirect);
        Assert.Equal(["ivan", "GroupA", "GroupB", "GroupC", "GroupD"], deepest.PathDisplayNames);
    }

    [Fact]
    public void StopsAtCyclesWithoutDuplicatingMemberships()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");
        var groupA = Group("A", "CN=A,OU=Groups,DC=adlab,DC=test", user.DistinguishedName, "CN=C,OU=Groups,DC=adlab,DC=test");
        var groupB = Group("B", "CN=B,OU=Groups,DC=adlab,DC=test", groupA.DistinguishedName);
        var groupC = Group("C", "CN=C,OU=Groups,DC=adlab,DC=test", groupB.DistinguishedName);

        var results = CreateService().GetMembershipsForUser(user, [user], [groupA, groupB, groupC]);

        Assert.Equal(3, results.Count);
        Assert.Equal(3, results.Select(result => result.TargetGroupObjectGuid).Distinct().Count());
        Assert.Equal(["A", "B", "C"], results.Select(result => result.TargetGroupName).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void StopsAtSelfReferencingGroup()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");
        var group = Group("A", "CN=A,OU=Groups,DC=adlab,DC=test", user.DistinguishedName, "CN=A,OU=Groups,DC=adlab,DC=test");

        var result = Assert.Single(CreateService().GetMembershipsForUser(user, [user], [group]));

        Assert.Equal(1, result.Depth);
        Assert.True(result.IsDirect);
    }

    [Fact]
    public void KeepsShortestPathWhenTargetHasSeveralPaths()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");
        var groupA = Group("A", "CN=A,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);
        var groupB = Group("B", "CN=B,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);
        var groupC = Group("C", "CN=C,OU=Groups,DC=adlab,DC=test", groupB.DistinguishedName);
        var target = Group("Target", "CN=Target,OU=Groups,DC=adlab,DC=test", groupA.DistinguishedName, groupC.DistinguishedName);

        var results = CreateService().GetMembershipsForUser(user, [user], [target, groupC, groupB, groupA]);
        var targetResult = Assert.Single(results, result => result.TargetGroupName == "Target");

        Assert.Equal(2, targetResult.Depth);
        Assert.Equal(["ivan", "A", "Target"], targetResult.PathDisplayNames);
    }

    [Fact]
    public void FindsSeveralParentGroupsForOneChildGroup()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");
        var groupA = Group("A", "CN=A,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);
        var groupB = Group("B", "CN=B,OU=Groups,DC=adlab,DC=test", groupA.DistinguishedName);
        var groupC = Group("C", "CN=C,OU=Groups,DC=adlab,DC=test", groupA.DistinguishedName);

        var results = CreateService().GetMembershipsForUser(user, [user], [groupC, groupA, groupB]);

        Assert.Equal(3, results.Count);
        Assert.Contains(results, result => result.TargetGroupName == "B" && result.Depth == 2);
        Assert.Contains(results, result => result.TargetGroupName == "C" && result.Depth == 2);
    }

    [Fact]
    public void MatchesDistinguishedNamesCaseInsensitively()
    {
        const string userDn = "CN=Ivan,OU=Users,DC=ADLAB,DC=TEST";
        var user = User(userDn, "ivan");
        var group = Group("HelpDesk", "CN=HelpDesk,OU=Groups,DC=adlab,DC=test", "cn=ivan,ou=users,dc=adlab,dc=test");

        var result = Assert.Single(CreateService().GetMembershipsForUser(user, [user], [group]));

        Assert.Equal("HelpDesk", result.TargetGroupName);
        Assert.True(result.IsDirect);
    }

    [Fact]
    public void ResolvesPrimaryGroupAsDirectMembership()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan", "S-1-5-21-1-2-3-1100", 513);
        var domainUsers = GroupWithSid("Domain Users", "CN=Domain Users,CN=Users,DC=adlab,DC=test", "S-1-5-21-1-2-3-513");

        var result = Assert.Single(CreateService().GetMembershipsForUser(user, [user], [domainUsers]));

        Assert.True(result.IsDirect);
        Assert.Equal(1, result.Depth);
        Assert.Equal(["ivan", "Domain Users"], result.PathDisplayNames);
    }

    [Fact]
    public void DoesNotDuplicatePrimaryGroupAlreadyPresentAsDirectEdge()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan", "S-1-5-21-1-2-3-1100", 513);
        var domainUsers = GroupWithSid(
            "Domain Users",
            "CN=Domain Users,CN=Users,DC=adlab,DC=test",
            "S-1-5-21-1-2-3-513",
            user.DistinguishedName);

        var result = Assert.Single(CreateService().GetMembershipsForUser(user, [user], [domainUsers]));

        Assert.Equal("Domain Users", result.TargetGroupName);
    }

    [Fact]
    public void MalformedPrimarySidDoesNotFailGraphAnalysis()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan", "not-a-sid", 513);
        var group = GroupWithSid("Domain Users", "CN=Domain Users,CN=Users,DC=adlab,DC=test", "S-1-5-21-1-2-3-513");

        var results = CreateService().GetMembershipsForUser(user, [user], [group]);

        Assert.Empty(results);
        Assert.False(PrimaryGroupResolver.TryCreatePrimaryGroupSid("not-a-sid", 513, out var primaryGroupSid));
        Assert.Null(primaryGroupSid);
    }

    [Fact]
    public void IgnoresReferencesMissingFromLoadedUsersAndGroups()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");
        var group = Group(
            "HelpDesk",
            "CN=HelpDesk,OU=Groups,DC=adlab,DC=test",
            user.DistinguishedName,
            "CN=S-1-5-21-9-8-7-6,CN=ForeignSecurityPrincipals,DC=adlab,DC=test");

        var result = Assert.Single(CreateService().GetMembershipsForUser(user, [user], [group]));

        Assert.Equal("HelpDesk", result.TargetGroupName);
    }

    [Fact]
    public void ReturnsEmptyListForUserWithoutGroups()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");

        Assert.Empty(CreateService().GetMembershipsForUser(user, [user], []));
    }

    [Fact]
    public void RespectsConfiguredMaximumDepth()
    {
        var user = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");
        var groupA = Group("A", "CN=A,OU=Groups,DC=adlab,DC=test", user.DistinguishedName);
        var groupB = Group("B", "CN=B,OU=Groups,DC=adlab,DC=test", groupA.DistinguishedName);
        var groupC = Group("C", "CN=C,OU=Groups,DC=adlab,DC=test", groupB.DistinguishedName);

        var results = CreateService(maxDepth: 2).GetMembershipsForUser(user, [user], [groupA, groupB, groupC]);

        Assert.Equal(2, results.Count);
        Assert.All(results, result => Assert.InRange(result.Depth, 1, 2));
    }

    [Fact]
    public void BuildsMembershipsForAllUsersFromOneGraph()
    {
        var userA = User("CN=Ivan,OU=Users,DC=adlab,DC=test", "ivan");
        var userB = User("CN=Maria,OU=Users,DC=adlab,DC=test", "maria");
        var group = Group("Staff", "CN=Staff,OU=Groups,DC=adlab,DC=test", userA.DistinguishedName, userB.DistinguishedName);

        var results = CreateService().BuildMembershipsForAllUsers([userB, userA], [group]);

        Assert.Equal(2, results.Count);
        Assert.Equal(["ivan", "maria"], results.Select(result => result.PrincipalName));
    }

    private static GroupGraphService CreateService(int maxDepth = 64)
    {
        return new GroupGraphService(
            NullLogger<GroupGraphService>.Instance,
            Options.Create(new GroupAnalysisOptions { MaxGroupNestingDepth = maxDepth }));
    }

    private static AdUserRecord User(string dn, string sam, string? sid = null, int? primaryGroupId = null)
    {
        return new AdUserRecord
        {
            ObjectGuid = Guid.NewGuid(),
            DistinguishedName = dn,
            SamAccountName = sam,
            Sid = sid,
            PrimaryGroupId = primaryGroupId
        };
    }

    private static AdGroupRecord Group(string name, string dn, params string[] members)
    {
        return new AdGroupRecord
        {
            ObjectGuid = Guid.NewGuid(),
            DistinguishedName = dn,
            CommonName = name,
            MemberDistinguishedNames = members
        };
    }

    private static AdGroupRecord GroupWithSid(string name, string dn, string sid, params string[] members)
    {
        return new AdGroupRecord
        {
            ObjectGuid = Guid.NewGuid(),
            DistinguishedName = dn,
            CommonName = name,
            Sid = sid,
            MemberDistinguishedNames = members
        };
    }
}
