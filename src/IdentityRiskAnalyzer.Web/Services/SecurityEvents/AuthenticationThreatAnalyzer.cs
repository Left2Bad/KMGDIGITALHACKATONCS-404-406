using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Services.SecurityEvents;

public sealed class AuthenticationThreatAnalyzer(IOptions<SecurityEventLogOptions> options)
{
    public IReadOnlyList<AuthenticationThreat> Analyze(IReadOnlyCollection<SecurityAuthenticationEvent> events,
        CancellationToken cancellationToken = default)
    {
        var config = options.Value;
        var failures = events.Where(item => item.IsFailedAuthentication && !string.IsNullOrWhiteSpace(NormalizeUserName(item.TargetUserName)))
            .DistinctBy(item => item.RecordId.HasValue ? $"id:{item.RecordId}" : $"entry:{item.EventId}:{item.TimestampUtc.Ticks}:{item.TargetUserName}:{item.SourceIpAddress}:{item.WorkstationName}")
            .OrderBy(item => item.TimestampUtc).Take(config.MaximumEvents).ToArray();
        var results = new List<AuthenticationThreat>();

        foreach (var group in failures.Select(item => (Event: item, Source: GetSource(item)))
            .Where(item => item.Source is not null).GroupBy(item => item.Source!, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var window = FindWindow(group.Select(item => item.Event).ToArray(), config.PasswordSprayWindowMinutes,
                config.PasswordSprayMinimumFailures, config.PasswordSprayMinimumDistinctUsers, cancellationToken);
            if (window is not null) results.Add(new AuthenticationThreat
            {
                Type = AuthenticationThreatType.PossiblePasswordSpray, Source = group.Key,
                WindowStartUtc = window[0].TimestampUtc, WindowEndUtc = window[^1].TimestampUtc,
                FailedAttempts = window.Length,
                AffectedUserNames = window.Select(item => NormalizeUserName(item.TargetUserName)!)
                    .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray()
            });
        }

        foreach (var group in failures.GroupBy(item => NormalizeUserName(item.TargetUserName)!, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var window = FindWindow(group.ToArray(), config.BruteForceWindowMinutes,
                config.BruteForceMinimumFailures, 1, cancellationToken);
            if (window is not null) results.Add(new AuthenticationThreat
            {
                Type = AuthenticationThreatType.PossibleBruteForce,
                Source = window.Select(GetSource).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1 ? GetSource(window[0]) : null,
                WindowStartUtc = window[0].TimestampUtc, WindowEndUtc = window[^1].TimestampUtc,
                FailedAttempts = window.Length, AffectedUserNames = [group.Key]
            });
        }

        return results;
    }

    private static SecurityAuthenticationEvent[]? FindWindow(SecurityAuthenticationEvent[] events, int minutes,
        int minimumFailures, int minimumUsers, CancellationToken cancellationToken)
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var left = 0;
        SecurityAuthenticationEvent[]? best = null;
        for (var right = 0; right < events.Length; right++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = NormalizeUserName(events[right].TargetUserName)!;
            counts[name] = counts.GetValueOrDefault(name) + 1;
            while (events[right].TimestampUtc - events[left].TimestampUtc > TimeSpan.FromMinutes(minutes))
            {
                var oldName = NormalizeUserName(events[left++].TargetUserName)!;
                if (--counts[oldName] == 0) counts.Remove(oldName);
            }
            if (right - left + 1 >= minimumFailures && counts.Count >= minimumUsers &&
                (best is null || right - left + 1 > best.Length))
                best = events[left..(right + 1)];
        }
        return best;
    }

    public static string? NormalizeUserName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        name = name.Trim();
        var slash = name.LastIndexOf('\\');
        if (slash >= 0) name = name[(slash + 1)..];
        var at = name.IndexOf('@');
        if (at > 0) name = name[..at];
        return name is "-" or "ANONYMOUS LOGON" or "SYSTEM" or "" ? null : name;
    }

    private static string? GetSource(SecurityAuthenticationEvent item) =>
        !string.IsNullOrWhiteSpace(item.SourceIpAddress) ? $"IP {item.SourceIpAddress}" :
        !string.IsNullOrWhiteSpace(item.WorkstationName) ? $"Workstation {item.WorkstationName}" : null;
}
