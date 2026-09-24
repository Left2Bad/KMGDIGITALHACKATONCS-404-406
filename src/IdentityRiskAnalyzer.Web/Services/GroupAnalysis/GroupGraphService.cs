using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Services.GroupAnalysis;

public sealed class GroupGraphService(
    ILogger<GroupGraphService> logger,
    IOptions<GroupAnalysisOptions> options)
{
    private static readonly StringComparer DistinguishedNameComparer = StringComparer.OrdinalIgnoreCase;
    private readonly int _maxGroupNestingDepth = options.Value.MaxGroupNestingDepth;

    public IReadOnlyList<GroupMembershipPathResult> GetMembershipsForUser(
        AdUserRecord user,
        IReadOnlyCollection<AdUserRecord> users,
        IReadOnlyCollection<AdGroupRecord> groups,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();

        var graph = BuildGraph(users, groups, cancellationToken);
        var canonicalUser = graph.UsersByDn.TryGetValue(user.DistinguishedName, out var indexedUser)
            ? indexedUser
            : user;

        logger.LogInformation(
            "Membership analysis started for principal {PrincipalObjectGuid}.",
            canonicalUser.ObjectGuid);
        var results = AnalyzeUser(graph, canonicalUser, cancellationToken, out var repeatedNodes, out var maxDepthHits);
        LogTraversalSummary(canonicalUser.ObjectGuid, results.Count, repeatedNodes, maxDepthHits);
        return SortResults(results);
    }

    public IReadOnlyList<GroupMembershipPathResult> BuildMembershipsForAllUsers(
        IReadOnlyCollection<AdUserRecord> users,
        IReadOnlyCollection<AdGroupRecord> groups,
        CancellationToken cancellationToken = default)
    {
        var graph = BuildGraph(users, groups, cancellationToken);
        logger.LogInformation("Membership analysis started for {UserCount} users.", graph.UsersByDn.Count);

        var results = new List<GroupMembershipPathResult>();
        var repeatedNodes = 0;
        var maxDepthHits = 0;
        foreach (var user in graph.UsersByDn.Values.OrderBy(GetPrincipalName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.AddRange(AnalyzeUser(graph, user, cancellationToken, out var userRepeatedNodes, out var userMaxDepthHits));
            repeatedNodes += userRepeatedNodes;
            maxDepthHits += userMaxDepthHits;
        }

        logger.LogInformation(
            "Membership analysis completed for {UserCount} users; found {PathCount} membership paths.",
            graph.UsersByDn.Count,
            results.Count);
        LogTraversalSummary(principalObjectGuid: null, results.Count, repeatedNodes, maxDepthHits);
        return SortResults(results);
    }

    private GroupGraph BuildGraph(
        IReadOnlyCollection<AdUserRecord> users,
        IReadOnlyCollection<AdGroupRecord> groups,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(users);
        ArgumentNullException.ThrowIfNull(groups);

        var usersByDn = new Dictionary<string, AdUserRecord>(DistinguishedNameComparer);
        foreach (var user in users)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(user.DistinguishedName))
            {
                logger.LogWarning("Ignoring a user with an empty distinguished name while building the group graph.");
                continue;
            }

            if (!usersByDn.TryAdd(user.DistinguishedName, user))
            {
                logger.LogWarning(
                    "Ignoring a duplicate user distinguished name while building the group graph. DN={DistinguishedName}.",
                    user.DistinguishedName);
            }
        }

        var groupsByDn = new Dictionary<string, AdGroupRecord>(DistinguishedNameComparer);
        foreach (var group in groups)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(group.DistinguishedName))
            {
                logger.LogWarning("Ignoring a group with an empty distinguished name while building the group graph.");
                continue;
            }

            if (!groupsByDn.TryAdd(group.DistinguishedName, group))
            {
                logger.LogWarning(
                    "Ignoring a duplicate group distinguished name while building the group graph. DN={DistinguishedName}.",
                    group.DistinguishedName);
            }
        }

        var groupsBySid = new Dictionary<string, AdGroupRecord>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in groupsByDn.Values)
        {
            if (string.IsNullOrWhiteSpace(group.Sid))
            {
                continue;
            }

            if (!groupsBySid.TryAdd(group.Sid, group))
            {
                logger.LogWarning("Ignoring a duplicate group SID while resolving primary groups. SID={Sid}.", group.Sid);
            }
        }

        var incompleteGroupMembersCount = groupsByDn.Values.Count(group => !group.MembersComplete);
        if (incompleteGroupMembersCount > 0)
        {
            logger.LogWarning(
                "Building the graph with {IncompleteGroupCount} groups whose direct member lists were incomplete; some membership paths may be missing.",
                incompleteGroupMembersCount);
        }

        var parentGroupsByMemberDn = new Dictionary<string, List<AdGroupRecord>>(DistinguishedNameComparer);
        var parentGroupDnsByMemberDn = new Dictionary<string, HashSet<string>>(DistinguishedNameComparer);
        var missingMemberDns = new HashSet<string>(DistinguishedNameComparer);
        var edgeCount = 0;

        void AddParentGroup(string memberDn, AdGroupRecord parentGroup)
        {
            if (!parentGroupsByMemberDn.TryGetValue(memberDn, out var parents))
            {
                parents = [];
                parentGroupsByMemberDn.Add(memberDn, parents);
                parentGroupDnsByMemberDn.Add(memberDn, new HashSet<string>(DistinguishedNameComparer));
            }

            if (parentGroupDnsByMemberDn[memberDn].Add(parentGroup.DistinguishedName))
            {
                parents.Add(parentGroup);
                edgeCount++;
            }
        }

        foreach (var group in groupsByDn.Values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var seenMembers = new HashSet<string>(DistinguishedNameComparer);
            foreach (var memberDn in group.MemberDistinguishedNames)
            {
                if (string.IsNullOrWhiteSpace(memberDn) || !seenMembers.Add(memberDn))
                {
                    continue;
                }

                if (usersByDn.TryGetValue(memberDn, out var memberUser))
                {
                    AddParentGroup(memberUser.DistinguishedName, group);
                }
                else if (groupsByDn.TryGetValue(memberDn, out var memberGroup))
                {
                    AddParentGroup(memberGroup.DistinguishedName, group);
                }
                else
                {
                    missingMemberDns.Add(memberDn);
                }
            }
        }

        var primaryMembershipsAdded = 0;
        foreach (var user in usersByDn.Values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(user.Sid) || user.PrimaryGroupId is null)
            {
                continue;
            }

            if (!PrimaryGroupResolver.TryCreatePrimaryGroupSid(user.Sid, user.PrimaryGroupId, out var primaryGroupSid))
            {
                logger.LogWarning(
                    "Could not derive a primary group SID from the user SID and primaryGroupID. User={UserObjectGuid}.",
                    user.ObjectGuid);
                continue;
            }

            if (primaryGroupSid is not null && groupsBySid.TryGetValue(primaryGroupSid, out var primaryGroup))
            {
                var previousEdgeCount = edgeCount;
                AddParentGroup(user.DistinguishedName, primaryGroup);
                if (edgeCount > previousEdgeCount)
                {
                    primaryMembershipsAdded++;
                }
            }
            else
            {
                logger.LogDebug(
                    "Could not find the primary group in the loaded group set for user {UserObjectGuid}.",
                    user.ObjectGuid);
            }
        }

        foreach (var parents in parentGroupsByMemberDn.Values)
        {
            parents.Sort(CompareGroups);
        }

        if (missingMemberDns.Count > 0)
        {
            logger.LogWarning(
                "The group graph ignored {MissingMemberCount} member DNs that were not present in the loaded users or groups.",
                missingMemberDns.Count);
        }

        logger.LogInformation(
            "Group graph built with {UserCount} users, {GroupCount} groups, and {EdgeCount} direct edges; added {PrimaryMembershipCount} primary-group memberships.",
            usersByDn.Count,
            groupsByDn.Count,
            edgeCount,
            primaryMembershipsAdded);

        return new GroupGraph(usersByDn, groupsByDn, groupsBySid, parentGroupsByMemberDn, edgeCount);
    }

    private IReadOnlyList<GroupMembershipPathResult> AnalyzeUser(
        GroupGraph graph,
        AdUserRecord user,
        CancellationToken cancellationToken,
        out int repeatedNodes,
        out int maxDepthHits)
    {
        repeatedNodes = 0;
        maxDepthHits = 0;
        if (!graph.ParentGroupsByMemberDn.TryGetValue(user.DistinguishedName, out var directGroups))
        {
            return Array.Empty<GroupMembershipPathResult>();
        }

        var results = new List<GroupMembershipPathResult>();
        var queue = new Queue<AdGroupRecord[]>();
        var visitedGroups = new HashSet<string>(DistinguishedNameComparer);
        foreach (var group in directGroups.OrderBy(group => group, Comparer<AdGroupRecord>.Create(CompareGroups)))
        {
            if (visitedGroups.Add(group.DistinguishedName))
            {
                queue.Enqueue([group]);
            }
            else
            {
                repeatedNodes++;
            }
        }

        var principalName = GetPrincipalName(user);
        while (queue.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var path = queue.Dequeue();
            var currentGroup = path[^1];
            // Depth counts group edges: direct membership is one edge and therefore Depth = 1.
            results.Add(CreateResult(user, principalName, path));

            if (path.Length >= _maxGroupNestingDepth)
            {
                if (graph.ParentGroupsByMemberDn.TryGetValue(currentGroup.DistinguishedName, out var deeperParents)
                    && deeperParents.Any(parent => !visitedGroups.Contains(parent.DistinguishedName)))
                {
                    maxDepthHits++;
                }

                continue;
            }

            if (!graph.ParentGroupsByMemberDn.TryGetValue(currentGroup.DistinguishedName, out var parents))
            {
                continue;
            }

            foreach (var parent in parents)
            {
                if (visitedGroups.Add(parent.DistinguishedName))
                {
                    var parentPath = new AdGroupRecord[path.Length + 1];
                    Array.Copy(path, parentPath, path.Length);
                    parentPath[^1] = parent;
                    queue.Enqueue(parentPath);
                }
                else
                {
                    repeatedNodes++;
                }
            }
        }

        return results;
    }

    private void LogTraversalSummary(Guid? principalObjectGuid, int pathCount, int repeatedNodes, int maxDepthHits)
    {
        if (repeatedNodes > 0)
        {
            logger.LogDebug("Skipped {RepeatedNodeCount} repeated or cyclic group nodes for principal {PrincipalObjectGuid}.", principalObjectGuid, repeatedNodes);
        }

        if (maxDepthHits > 0)
        {
            logger.LogWarning(
                "Stopped traversal at the configured maximum depth {MaxDepth} for {TruncatedPathCount} branches; principal={PrincipalObjectGuid}.",
                _maxGroupNestingDepth,
                maxDepthHits,
                principalObjectGuid);
        }

        logger.LogDebug(
            "Membership paths found: {PathCount} for principal {PrincipalObjectGuid}.",
            pathCount,
            principalObjectGuid);
    }

    private static GroupMembershipPathResult CreateResult(
        AdUserRecord user,
        string principalName,
        IReadOnlyList<AdGroupRecord> path)
    {
        var targetGroup = path[^1];
        var distinguishedNames = new string[path.Count + 1];
        distinguishedNames[0] = user.DistinguishedName;
        var displayNames = new string[path.Count + 1];
        displayNames[0] = principalName;

        for (var index = 0; index < path.Count; index++)
        {
            distinguishedNames[index + 1] = path[index].DistinguishedName;
            displayNames[index + 1] = GetGroupName(path[index]);
        }

        return new GroupMembershipPathResult
        {
            PrincipalObjectGuid = user.ObjectGuid,
            PrincipalName = principalName,
            TargetGroupObjectGuid = targetGroup.ObjectGuid,
            TargetGroupName = GetGroupName(targetGroup),
            TargetGroupDistinguishedName = targetGroup.DistinguishedName,
            IsDirect = path.Count == 1,
            Depth = path.Count,
            PathDistinguishedNames = Array.AsReadOnly(distinguishedNames),
            PathDisplayNames = Array.AsReadOnly(displayNames)
        };
    }

    private static IReadOnlyList<GroupMembershipPathResult> SortResults(IEnumerable<GroupMembershipPathResult> results)
    {
        return results
            .OrderBy(result => result.PrincipalName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(result => result.Depth)
            .ThenBy(result => result.TargetGroupName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(result => result.TargetGroupDistinguishedName, DistinguishedNameComparer)
            .ToArray();
    }

    private static string GetPrincipalName(AdUserRecord user)
    {
        return user.SamAccountName
            ?? user.UserPrincipalName
            ?? user.DisplayName
            ?? user.DistinguishedName;
    }

    private static string GetGroupName(AdGroupRecord group)
    {
        return group.CommonName
            ?? group.SamAccountName
            ?? group.DistinguishedName;
    }

    private static int CompareGroups(AdGroupRecord left, AdGroupRecord right)
    {
        var byName = StringComparer.OrdinalIgnoreCase.Compare(GetGroupName(left), GetGroupName(right));
        if (byName != 0)
        {
            return byName;
        }

        var byDn = DistinguishedNameComparer.Compare(left.DistinguishedName, right.DistinguishedName);
        return byDn != 0 ? byDn : left.ObjectGuid.CompareTo(right.ObjectGuid);
    }

    private sealed record GroupGraph(
        Dictionary<string, AdUserRecord> UsersByDn,
        Dictionary<string, AdGroupRecord> GroupsByDn,
        Dictionary<string, AdGroupRecord> GroupsBySid,
        Dictionary<string, List<AdGroupRecord>> ParentGroupsByMemberDn,
        int EdgeCount);
}
