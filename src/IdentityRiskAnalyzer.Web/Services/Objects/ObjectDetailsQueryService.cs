using System.Text.Json;
using IdentityRiskAnalyzer.Web.Data;
using IdentityRiskAnalyzer.Web.Domain.Entities;
using IdentityRiskAnalyzer.Web.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace IdentityRiskAnalyzer.Web.Services.Objects;

// Historical read model: no LDAP, risk rules, or current scoring settings are involved.
public sealed class ObjectDetailsQueryService(AppDbContext db, ILogger<ObjectDetailsQueryService> logger)
{
    private const int MembershipPageSize = 50;

    public async Task<AccountDetailsViewModel?> GetAsync(
        long scanId, Guid objectGuid, int membershipPage = 1, CancellationToken cancellationToken = default)
    {
        var run = await db.ScanRuns.AsNoTracking()
            .Where(item => item.Id == scanId)
            .Select(item => new { item.Id, item.StartedAtUtc, item.Status })
            .SingleOrDefaultAsync(cancellationToken);
        if (run is null) return null;

        var account = await db.AdObjectSnapshots.AsNoTracking()
            .Where(item => item.ScanRunId == scanId && item.ObjectGuid == objectGuid)
            .SingleOrDefaultAsync(cancellationToken);
        if (account is null) return null;

        var storedFindings = await db.RiskFindings.AsNoTracking()
            .Where(item => item.ScanRunId == scanId && item.ObjectGuid == objectGuid)
            .OrderByDescending(item => item.Severity)
            .ThenByDescending(item => item.RiskPoints)
            .ThenBy(item => item.RuleId)
            .ThenBy(item => item.Title)
            .ThenBy(item => item.Id)
            .ToListAsync(cancellationToken);
        var findings = storedFindings.Select(item => new HistoricalFindingViewModel
        {
            Severity = item.Severity, RuleId = item.RuleId, Category = item.Category,
            Title = item.Title, Description = item.Description, Evidence = item.Evidence,
            Recommendation = item.Recommendation, RiskPoints = item.RiskPoints
        }).ToArray();

        var privilegedRows = await db.GroupMemberships.AsNoTracking()
            .Where(item => item.ScanRunId == scanId && item.PrincipalObjectGuid == objectGuid && item.IsPrivileged)
            .OrderBy(item => item.Depth).ThenBy(item => item.GroupName).ThenBy(item => item.Id)
            .ToListAsync(cancellationToken);
        var membershipsQuery = db.GroupMemberships.AsNoTracking()
            .Where(item => item.ScanRunId == scanId && item.PrincipalObjectGuid == objectGuid);
        var membershipCount = await membershipsQuery.CountAsync(cancellationToken);
        var pageCount = Math.Max(1, (membershipCount + MembershipPageSize - 1) / MembershipPageSize);
        var page = Math.Clamp(membershipPage, 1, pageCount);
        var membershipRows = await membershipsQuery
            .OrderBy(item => item.Depth).ThenBy(item => item.GroupName).ThenBy(item => item.Id)
            .Skip((page - 1) * MembershipPageSize).Take(MembershipPageSize)
            .ToListAsync(cancellationToken);

        var delegationRows = await db.DelegationRecords.AsNoTracking()
            .Where(item => item.ScanRunId == scanId && item.ObjectGuid == objectGuid)
            .OrderBy(item => item.DelegationType).ThenBy(item => item.Id)
            .ToListAsync(cancellationToken);

        long accumulated = 0;
        foreach (var finding in findings)
        {
            var contribution = finding.ScoreContribution;
            accumulated = accumulated > long.MaxValue - contribution ? long.MaxValue : accumulated + contribution;
        }

        return new AccountDetailsViewModel
        {
            ScanRunId = run.Id,
            ScanTimestampUtc = run.StartedAtUtc,
            ScanStatus = run.Status,
            ObjectGuid = account.ObjectGuid,
            ObjectType = account.ObjectType,
            SamAccountName = account.SamAccountName,
            DisplayName = account.DisplayName,
            UserPrincipalName = account.UserPrincipalName,
            DistinguishedName = account.DistinguishedName,
            Sid = account.Sid,
            Enabled = account.Enabled,
            Locked = account.Locked,
            AccountExpired = account.AccountExpired,
            LastKnownActivityUtc = account.LastKnownActivityUtc,
            PasswordLastSetUtc = account.PasswordLastSetUtc,
            PasswordNeverExpires = account.PasswordNeverExpires,
            IsServiceAccount = account.IsServiceAccount,
            IsPrivileged = account.IsPrivileged,
            RiskScore = account.RiskScore,
            RiskLevel = account.RiskLevel,
            AccumulatedPoints = accumulated,
            Findings = findings,
            PrivilegeMemberships = privilegedRows.Select(row => ToMembership(row, scanId, objectGuid)).ToArray(),
            GroupMemberships = membershipRows.Select(row => ToMembership(row, scanId, objectGuid)).ToArray(),
            GroupMembershipCount = membershipCount,
            MembershipPage = page,
            MembershipPageSize = MembershipPageSize,
            DelegationRecords = delegationRows.Select(row => ToDelegation(row, scanId, objectGuid)).ToArray()
        };
    }

    private HistoricalMembershipViewModel ToMembership(GroupMembership row, long scanId, Guid objectGuid)
    {
        var parsed = TryReadStringArray(row.PathJson, scanId, objectGuid, row.Id, "PathJson");
        return new HistoricalMembershipViewModel
        {
            GroupObjectGuid = row.GroupObjectGuid,
            GroupName = row.GroupName,
            GroupDistinguishedName = row.GroupDistinguishedName,
            IsDirect = row.IsDirect,
            Depth = row.Depth,
            IsPrivileged = row.IsPrivileged,
            PathDisplayNames = parsed.Values,
            PathAvailable = parsed.Valid
        };
    }

    private HistoricalDelegationViewModel ToDelegation(DelegationRecord row, long scanId, Guid objectGuid)
    {
        if (row.TargetsJson is null)
        {
            return new HistoricalDelegationViewModel { DelegationType = row.DelegationType, TargetsAvailable = true };
        }
        var parsed = TryReadStringArray(row.TargetsJson, scanId, objectGuid, row.Id, "TargetsJson");
        return new HistoricalDelegationViewModel
        {
            DelegationType = row.DelegationType,
            Targets = parsed.Values,
            TargetsAvailable = parsed.Valid
        };
    }

    private (IReadOnlyList<string> Values, bool Valid) TryReadStringArray(
        string json, long scanId, Guid objectGuid, long recordId, string field)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                throw new JsonException("Expected a JSON array.");
            var values = new List<string>();
            foreach (var element in document.RootElement.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.String)
                    throw new JsonException("Expected string elements.");
                values.Add(element.GetString()!);
            }
            return (values, true);
        }
        catch (JsonException exception)
        {
            logger.LogWarning(exception, "Could not parse {Field} in scan {ScanRunId}, object {ObjectGuid}, record {RecordId}.",
                field, scanId, objectGuid, recordId);
            return ([], false);
        }
    }
}
