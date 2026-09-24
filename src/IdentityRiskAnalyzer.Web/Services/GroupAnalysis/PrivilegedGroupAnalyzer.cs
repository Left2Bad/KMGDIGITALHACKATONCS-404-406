using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Services.GroupAnalysis;

public sealed class PrivilegedGroupAnalyzer(
    ILogger<PrivilegedGroupAnalyzer> logger,
    IOptions<PrivilegeAnalysisOptions> options)
{
    private readonly IReadOnlyList<PrivilegedGroupDefinition> _definitions = options.Value.PrivilegedGroups;

    public PrivilegeAnalysisResult AnalyzeUser(
        AdUserRecord user,
        IReadOnlyCollection<GroupMembershipPathResult> membershipPaths,
        IReadOnlyCollection<AdGroupRecord> groups,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(membershipPaths);
        ArgumentNullException.ThrowIfNull(groups);

        var groupIndex = BuildGroupIndex(groups, out var classifications, out var matchedDefinitions, cancellationToken);
        LogMissingDefinitions(matchedDefinitions);
        return CreateResult(user, membershipPaths, groupIndex, classifications, cancellationToken);
    }

    public IReadOnlyList<PrivilegeAnalysisResult> AnalyzeAllUsers(
        IReadOnlyCollection<AdUserRecord> users,
        IReadOnlyCollection<GroupMembershipPathResult> membershipPaths,
        IReadOnlyCollection<AdGroupRecord> groups,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(users);
        ArgumentNullException.ThrowIfNull(membershipPaths);
        ArgumentNullException.ThrowIfNull(groups);
        logger.LogInformation("Privilege analysis started for {UserCount} users.", users.Count);

        var groupIndex = BuildGroupIndex(groups, out var classifications, out var matchedDefinitions, cancellationToken);
        var pathsByUser = membershipPaths
            .GroupBy(path => path.PrincipalObjectGuid)
            .ToDictionary(group => group.Key, group => (IReadOnlyCollection<GroupMembershipPathResult>)group.ToArray());

        var results = new List<PrivilegeAnalysisResult>(users.Count);
        foreach (var user in users.OrderBy(GetUserName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            pathsByUser.TryGetValue(user.ObjectGuid, out var userPaths);
            results.Add(CreateResult(user, userPaths ?? Array.Empty<GroupMembershipPathResult>(), groupIndex, classifications, cancellationToken));
        }

        LogMissingDefinitions(matchedDefinitions);
        var privilegedResults = results.Where(result => result.IsPrivileged).ToArray();
        var directCount = privilegedResults.Sum(result => result.PrivilegedMemberships.Count(item => item.IsDirect));
        var nestedCount = privilegedResults.Sum(result => result.PrivilegedMemberships.Count(item => !item.IsDirect));
        logger.LogInformation(
            "Privilege analysis completed: {UsersAnalysed} users, {PrivilegedUsers} privileged users, {DirectMemberships} direct and {NestedMemberships} nested privileged memberships.",
            results.Count,
            privilegedResults.Length,
            directCount,
            nestedCount);

        return results;
    }

    private Dictionary<Guid, AdGroupRecord> BuildGroupIndex(
        IReadOnlyCollection<AdGroupRecord> groups,
        out Dictionary<Guid, GroupClassification> classifications,
        out HashSet<int> matchedDefinitions,
        CancellationToken cancellationToken)
    {
        var groupIndex = new Dictionary<Guid, AdGroupRecord>();
        classifications = [];
        matchedDefinitions = [];

        foreach (var group in groups)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!groupIndex.TryAdd(group.ObjectGuid, group))
            {
                logger.LogWarning("Ignoring duplicate group object GUID during privilege analysis. ObjectGuid={ObjectGuid}.", group.ObjectGuid);
                continue;
            }

            var matches = new List<(int DefinitionIndex, PrivilegedGroupMatchMethod Method)>();
            for (var index = 0; index < _definitions.Count; index++)
            {
                if (PrivilegedGroupMatcher.TryMatch(group, _definitions[index], out var method))
                {
                    matches.Add((index, method));
                }
            }

            if (matches.Count == 0)
            {
                continue;
            }

            foreach (var match in matches)
            {
                matchedDefinitions.Add(match.DefinitionIndex);
            }

            var bestMatch = matches
                .OrderBy(match => MatchPriority(match.Method))
                .ThenBy(match => match.DefinitionIndex)
                .First();
            classifications.Add(group.ObjectGuid, new GroupClassification(
                bestMatch.Method,
                _definitions[bestMatch.DefinitionIndex].Category));
        }

        return groupIndex;
    }

    private PrivilegeAnalysisResult CreateResult(
        AdUserRecord user,
        IReadOnlyCollection<GroupMembershipPathResult> membershipPaths,
        IReadOnlyDictionary<Guid, AdGroupRecord> groupIndex,
        IReadOnlyDictionary<Guid, GroupClassification> classifications,
        CancellationToken cancellationToken)
    {
        var privilegedMemberships = new Dictionary<Guid, PrivilegedMembershipResult>();
        foreach (var path in membershipPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!TryGetClassification(path, groupIndex, classifications, out var classification))
            {
                continue;
            }

            groupIndex.TryGetValue(path.TargetGroupObjectGuid, out var group);
            var item = new PrivilegedMembershipResult
            {
                GroupObjectGuid = path.TargetGroupObjectGuid,
                GroupName = group is null ? path.TargetGroupName : GetGroupName(group),
                GroupDistinguishedName = group?.DistinguishedName ?? path.TargetGroupDistinguishedName,
                GroupSid = group?.Sid,
                IsDirect = path.IsDirect,
                Depth = path.Depth,
                PathDisplayNames = path.PathDisplayNames,
                PathDistinguishedNames = path.PathDistinguishedNames,
                MatchMethod = classification.MatchMethod,
                Category = classification.Category
            };

            if (!privilegedMemberships.TryGetValue(path.TargetGroupObjectGuid, out var current)
                || path.Depth < current.Depth)
            {
                privilegedMemberships[path.TargetGroupObjectGuid] = item;
            }
        }

        var memberships = privilegedMemberships.Values
            .OrderBy(item => item.Depth)
            .ThenBy(item => item.GroupName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.GroupDistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new PrivilegeAnalysisResult
        {
            UserObjectGuid = user.ObjectGuid,
            UserName = GetUserName(user),
            PrivilegedMemberships = memberships
        };
    }

    private bool TryGetClassification(
        GroupMembershipPathResult path,
        IReadOnlyDictionary<Guid, AdGroupRecord> groupIndex,
        IReadOnlyDictionary<Guid, GroupClassification> classifications,
        out GroupClassification classification)
    {
        if (classifications.TryGetValue(path.TargetGroupObjectGuid, out classification!))
        {
            return true;
        }

        // A manually supplied path may outlive a partial group collection; configured name matching remains a safe fallback.
        var matchingDefinition = _definitions
            .Select((definition, index) => (definition, index))
            .Where(item => PrivilegedGroupMatcher.MatchesConfiguredName(path.TargetGroupName, item.definition))
            .OrderBy(item => item.index)
            .FirstOrDefault();
        if (matchingDefinition.definition is null)
        {
            classification = default!;
            return false;
        }

        if (groupIndex.TryGetValue(path.TargetGroupObjectGuid, out var group)
            && PrivilegedGroupMatcher.TryMatch(group, matchingDefinition.definition, out var method))
        {
            classification = new GroupClassification(method, matchingDefinition.definition.Category);
            return true;
        }

        classification = new GroupClassification(
            PrivilegedGroupMatchMethod.ConfiguredName,
            matchingDefinition.definition.Category);
        return true;
    }

    private void LogMissingDefinitions(IReadOnlySet<int> matchedDefinitions)
    {
        for (var index = 0; index < _definitions.Count; index++)
        {
            var definition = _definitions[index];
            if (definition.Enabled && !matchedDefinitions.Contains(index))
            {
                logger.LogWarning(
                    "Configured privileged group was not found in the collected AD groups. Group={GroupName}.",
                    definition.Name);
            }
        }
    }

    private static int MatchPriority(PrivilegedGroupMatchMethod method) => method switch
    {
        PrivilegedGroupMatchMethod.Sid => 0,
        PrivilegedGroupMatchMethod.Rid => 1,
        PrivilegedGroupMatchMethod.ConfiguredName => 2,
        _ => 3
    };

    private static string GetUserName(AdUserRecord user) =>
        user.SamAccountName ?? user.UserPrincipalName ?? user.DisplayName ?? user.DistinguishedName;

    private static string GetGroupName(AdGroupRecord group) =>
        group.CommonName ?? group.SamAccountName ?? group.DistinguishedName;

    private sealed record GroupClassification(PrivilegedGroupMatchMethod MatchMethod, string? Category);
}
