using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

namespace IdentityRiskAnalyzer.Tests;

public class ActiveDirectoryGroupTests
{
    [Fact]
    public void IdentifiesSecurityGlobalGroup()
    {
        const long groupType = unchecked((long)0x80000002);

        Assert.True(ActiveDirectoryGroupTypeHelper.IsSecurityGroup(groupType));
        Assert.Equal(AdGroupScope.Global, ActiveDirectoryGroupTypeHelper.GetScope(groupType));
        Assert.Equal("Security · Global", ActiveDirectoryGroupTypeHelper.Describe(groupType));
    }

    [Fact]
    public void IdentifiesSecurityDomainLocalGroup()
    {
        const long groupType = unchecked((long)0x80000004);

        Assert.True(ActiveDirectoryGroupTypeHelper.IsSecurityGroup(groupType));
        Assert.Equal(AdGroupScope.DomainLocal, ActiveDirectoryGroupTypeHelper.GetScope(groupType));
        Assert.Equal("Security · Domain Local", ActiveDirectoryGroupTypeHelper.Describe(groupType));
    }

    [Fact]
    public void IdentifiesSecurityUniversalGroup()
    {
        const long groupType = unchecked((long)0x80000008);

        Assert.True(ActiveDirectoryGroupTypeHelper.IsSecurityGroup(groupType));
        Assert.Equal(AdGroupScope.Universal, ActiveDirectoryGroupTypeHelper.GetScope(groupType));
        Assert.Equal("Security · Universal", ActiveDirectoryGroupTypeHelper.Describe(groupType));
    }

    [Fact]
    public void IdentifiesDistributionGroup()
    {
        const long groupType = 0x00000002;

        Assert.False(ActiveDirectoryGroupTypeHelper.IsSecurityGroup(groupType));
        Assert.Equal(AdGroupScope.Global, ActiveDirectoryGroupTypeHelper.GetScope(groupType));
        Assert.Equal("Distribution · Global", ActiveDirectoryGroupTypeHelper.Describe(groupType));
    }

    [Fact]
    public void ReadsMissingMemberAttributeAsCompleteEmptyList()
    {
        var result = GroupMemberAttributeReader.Read(
            Array.Empty<KeyValuePair<string, IReadOnlyList<string>>>());

        Assert.Empty(result.Members);
        Assert.False(result.HasMemberAttribute);
        Assert.True(result.IsComplete);
    }

    [Fact]
    public void ReadsOneOrdinaryMember()
    {
        var result = GroupMemberAttributeReader.Read(
        [
            Attribute("member", "CN=Ivan,OU=Users,DC=adlab,DC=test")
        ]);

        Assert.Equal(["CN=Ivan,OU=Users,DC=adlab,DC=test"], result.Members);
        Assert.True(result.IsComplete);
    }

    [Fact]
    public void ReadsSeveralOrdinaryMembers()
    {
        var result = GroupMemberAttributeReader.Read(
        [
            Attribute("member", "CN=Ivan,OU=Users,DC=adlab,DC=test", "CN=HelpDesk,OU=Groups,DC=adlab,DC=test")
        ]);

        Assert.Equal(2, result.Members.Count);
        Assert.True(result.IsComplete);
    }

    [Theory]
    [InlineData("member;range=0-1499", 0, 1499, false, 1500)]
    [InlineData("member;range=1500-2999", 1500, 2999, false, 3000)]
    public void ParsesNonFinalMemberRanges(string attributeName, long start, long end, bool isFinal, long nextStart)
    {
        Assert.True(LdapAttributeRangeParser.TryParse(attributeName, out var range));
        Assert.Equal(start, range.Start);
        Assert.Equal(end, range.End);
        Assert.Equal(isFinal, range.IsFinal);
        Assert.Equal(nextStart, range.NextStart);
    }

    [Fact]
    public void ParsesFinalMemberRange()
    {
        Assert.True(LdapAttributeRangeParser.TryParse("member;range=3000-*", out var range));
        Assert.Equal(3000, range.Start);
        Assert.Null(range.End);
        Assert.True(range.IsFinal);
        Assert.Null(range.NextStart);
    }

    [Fact]
    public void ReadsNonFinalRangeAndComputesNextStartFromReturnedEnd()
    {
        var result = GroupMemberAttributeReader.Read(
        [
            Attribute("member;range=0-1499", "CN=A,OU=Groups,DC=adlab,DC=test")
        ]);

        Assert.True(result.HasRangedAttribute);
        Assert.False(result.IsComplete);
        Assert.Equal(0, result.FirstRangeStart);
        Assert.Equal(1500, result.NextRangeStart);
        Assert.Single(result.Members);
    }

    [Fact]
    public void ReadsFinalRangeAsComplete()
    {
        var result = GroupMemberAttributeReader.Read(
        [
            Attribute("member;range=3000-*", "CN=Last,OU=Users,DC=adlab,DC=test")
        ]);

        Assert.True(result.HasRangedAttribute);
        Assert.True(result.IsComplete);
        Assert.Null(result.NextRangeStart);
    }

    [Fact]
    public void MarksMalformedRangedAttributeIncomplete()
    {
        var result = GroupMemberAttributeReader.Read(
        [
            Attribute("member;range=abc-def", "CN=A,OU=Groups,DC=adlab,DC=test")
        ]);

        Assert.True(result.HasRangedAttribute);
        Assert.True(result.IsMalformed);
        Assert.False(result.IsComplete);
        Assert.Null(result.NextRangeStart);
    }

    [Theory]
    [InlineData("member;range=abc-def")]
    [InlineData("member;range=")]
    [InlineData("randomAttribute")]
    [InlineData("member;range=10-9")]
    public void RejectsMalformedOrUnrelatedAttributeNames(string attributeName)
    {
        Assert.False(LdapAttributeRangeParser.TryParse(attributeName, out _));
    }

    [Fact]
    public void AccumulatesMemberChunksWithoutCaseInsensitiveDuplicates()
    {
        var accumulator = new MemberDnAccumulator();
        accumulator.AddRange(["CN=A,OU=Groups,DC=adlab,DC=test", "CN=B,OU=Groups,DC=adlab,DC=test", "CN=C,OU=Groups,DC=adlab,DC=test"]);
        accumulator.AddRange(["cn=c,ou=groups,dc=adlab,dc=test", "CN=D,OU=Groups,DC=adlab,DC=test", "CN=E,OU=Groups,DC=adlab,DC=test"]);

        Assert.Equal(5, accumulator.Count);
        Assert.Equal(
            ["CN=A,OU=Groups,DC=adlab,DC=test", "CN=B,OU=Groups,DC=adlab,DC=test", "CN=C,OU=Groups,DC=adlab,DC=test", "CN=D,OU=Groups,DC=adlab,DC=test", "CN=E,OU=Groups,DC=adlab,DC=test"],
            accumulator.ToReadOnlyList());
    }

    [Fact]
    public void RangeProgressGuardRejectsRepeatedOrNonAdvancingRanges()
    {
        var guard = new LdapRangeProgressGuard();

        Assert.True(guard.TryRegisterRequest(1500));
        Assert.False(guard.TryRegisterRequest(1500));
        Assert.False(guard.TryRegisterRequest(-1));
        Assert.True(LdapRangeProgressGuard.Advances(1500, 3000));
        Assert.False(LdapRangeProgressGuard.Advances(1500, 1500));
        Assert.False(LdapRangeProgressGuard.Advances(1500, null));
    }

    private static KeyValuePair<string, IReadOnlyList<string>> Attribute(string name, params string[] values)
    {
        return new KeyValuePair<string, IReadOnlyList<string>>(name, values);
    }
}
