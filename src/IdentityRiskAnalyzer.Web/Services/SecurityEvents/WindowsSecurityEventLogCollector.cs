using System.Diagnostics.Eventing.Reader;
using System.Security;
using System.Xml;
using System.Runtime.Versioning;
using IdentityRiskAnalyzer.Web.Domain.Enums;
using IdentityRiskAnalyzer.Web.Domain.Models;
using IdentityRiskAnalyzer.Web.Options;
using Microsoft.Extensions.Options;

namespace IdentityRiskAnalyzer.Web.Services.SecurityEvents;

public sealed class WindowsSecurityEventLogCollector(
    IOptions<SecurityEventLogOptions> eventOptions,
    IOptions<ActiveDirectoryOptions> adOptions,
    TimeProvider clock,
    ILogger<WindowsSecurityEventLogCollector> logger) : ISecurityEventLogCollector
{
    public SecurityEventCollectionResult Collect(CancellationToken cancellationToken)
    {
        var options = eventOptions.Value;
        if (!options.Enabled) return new() { Status = SecurityEventCollectionStatus.Disabled };
        if (!OperatingSystem.IsWindows()) return new()
        {
            Status = SecurityEventCollectionStatus.Unavailable,
            ErrorMessage = "Windows Security Event Log is unavailable on this platform."
        };

        cancellationToken.ThrowIfCancellationRequested();
        var server = string.IsNullOrWhiteSpace(options.Server) ? adOptions.Value.Server : options.Server;
        var cutoff = clock.GetUtcNow().AddMinutes(-options.LookbackMinutes);
        var ids = string.Join(" or ", options.IncludeEventIds.Select(id => $"EventID={id}"));
        var lookbackMilliseconds = checked((long)options.LookbackMinutes * 60_000);
        var xpath = $"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {lookbackMilliseconds}]]]";
        var events = new List<SecurityAuthenticationEvent>();
        var seenIds = new HashSet<long>();
        var read = 0;
        var skipped = 0;
        var truncated = false;
        try
        {
            using var session = CreateSession(server, adOptions.Value);
            var query = new EventLogQuery("Security", PathType.LogName, xpath) { Session = session, ReverseDirection = true };
            using var reader = new EventLogReader(query);
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (read >= options.MaximumEvents) { truncated = true; break; }
                read++;
                try
                {
                    if (record.RecordId.HasValue && !seenIds.Add(record.RecordId.Value)) continue;
                    if (!record.TimeCreated.HasValue) { skipped++; continue; }
                    var timestamp = new DateTimeOffset(record.TimeCreated.Value.ToUniversalTime());
                    if (timestamp < cutoff) continue;
                    events.Add(SecurityEventXmlParser.Parse(record.Id, timestamp, record.RecordId, record.ToXml()));
                }
                catch (Exception exception) when (exception is XmlException or ArgumentException or EventLogException)
                {
                    skipped++;
                    logger.LogWarning("Security Event Log record {RecordId} could not be parsed: {ErrorType}.",
                        record.RecordId, exception.GetType().Name);
                }
            }
            logger.LogInformation("Security events from {Server}: read {Read}, normalized {Normalized}, skipped {Skipped}, truncated {Truncated}.",
                server, read, events.Count, skipped, truncated);
            return new() { Status = SecurityEventCollectionStatus.Success, Events = events,
                EventsRead = read, EventsSkipped = skipped, WasTruncated = truncated };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is EventLogException or UnauthorizedAccessException or SecurityException or IOException)
        {
            logger.LogWarning(exception, "Security Event Log on {Server} is unavailable.", server);
            return new() { Status = SecurityEventCollectionStatus.Unavailable,
                ErrorMessage = "Security Event Log is unavailable or access was denied." };
        }
    }

    [SupportedOSPlatform("windows")]
    private static EventLogSession CreateSession(string server, ActiveDirectoryOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Username) || string.IsNullOrEmpty(options.Password))
            return new EventLogSession(server);

        var user = options.Username;
        string? domain = null;
        var slash = user.IndexOf('\\');
        if (slash >= 0) { domain = user[..slash]; user = user[(slash + 1)..]; }
        using var password = new SecureString();
        foreach (var character in options.Password) password.AppendChar(character);
        password.MakeReadOnly();
        return new EventLogSession(server, domain, user, password, SessionAuthentication.Default);
    }
}
