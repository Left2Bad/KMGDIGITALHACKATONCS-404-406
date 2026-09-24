using System.DirectoryServices.Protocols;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public static class GroupMemberAttributeReader
{
    public static GroupMemberAttributeBatch Read(SearchResultEntry entry)
    {
        var attributes = ActiveDirectoryAttributeConverter.GetAttributeNames(entry)
            .Where(IsMemberAttribute)
            .Select(name => new KeyValuePair<string, IReadOnlyList<string>>(
                name,
                ActiveDirectoryAttributeConverter.GetMultiValueStrings(entry, name)));

        return Read(attributes);
    }

    public static GroupMemberAttributeBatch Read(
        IEnumerable<KeyValuePair<string, IReadOnlyList<string>>> namedAttributes)
    {
        var members = new MemberDnAccumulator();
        var hasAttribute = false;
        var hasOrdinaryAttribute = false;
        var hasRangedAttribute = false;
        var hasFinalRange = false;
        var malformed = false;
        long? firstRangeStart = null;
        long? nextRangeStart = null;

        foreach (var (attributeName, values) in namedAttributes)
        {
            if (string.Equals(attributeName, "member", StringComparison.OrdinalIgnoreCase))
            {
                hasAttribute = true;
                hasOrdinaryAttribute = true;
                members.AddRange(values);
                continue;
            }

            if (!attributeName.StartsWith("member;range=", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            hasAttribute = true;
            hasRangedAttribute = true;
            members.AddRange(values);

            if (!LdapAttributeRangeParser.TryParse(attributeName, out var range))
            {
                malformed = true;
                continue;
            }

            firstRangeStart = firstRangeStart is null ? range.Start : Math.Min(firstRangeStart.Value, range.Start);
            if (range.IsFinal)
            {
                hasFinalRange = true;
                continue;
            }

            if (range.NextStart is not long rangeNextStart)
            {
                malformed = true;
                continue;
            }

            nextRangeStart = nextRangeStart is null
                ? rangeNextStart
                : Math.Max(nextRangeStart.Value, rangeNextStart);
        }

        var complete = !hasRangedAttribute || (!malformed && hasFinalRange);
        if (!hasAttribute || hasOrdinaryAttribute && !hasRangedAttribute)
        {
            complete = true;
        }

        return new GroupMemberAttributeBatch(
            members.ToReadOnlyList(),
            hasAttribute,
            hasRangedAttribute,
            complete,
            malformed,
            firstRangeStart,
            malformed || hasFinalRange ? null : nextRangeStart);
    }

    private static bool IsMemberAttribute(string name)
    {
        return string.Equals(name, "member", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("member;range=", StringComparison.OrdinalIgnoreCase);
    }
}
