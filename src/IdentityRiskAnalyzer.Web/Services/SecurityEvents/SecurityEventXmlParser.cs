using System.Xml.Linq;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.SecurityEvents;

public static class SecurityEventXmlParser
{
    public static SecurityAuthenticationEvent Parse(int eventId, DateTimeOffset timestamp, long? recordId, string xml)
    {
        var document = XDocument.Parse(xml);
        var values = document.Descendants().Where(element => element.Name.LocalName == "Data")
            .Select(element => (Name: (string?)element.Attribute("Name"), Value: element.Value))
            .Where(item => !string.IsNullOrWhiteSpace(item.Name))
            .GroupBy(item => item.Name!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().Value, StringComparer.OrdinalIgnoreCase);

        string? Get(params string[] names)
        {
            foreach (var name in names)
            {
                if (values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) && value != "-")
                    return value.Trim();
            }
            return null;
        }

        return new SecurityAuthenticationEvent
        {
            EventId = eventId, TimestampUtc = timestamp.ToUniversalTime(), RecordId = recordId,
            TargetUserName = Get("TargetUserName", "AccountName"),
            TargetDomainName = Get("TargetDomainName", "AccountDomain"),
            SourceIpAddress = Get("IpAddress", "ClientAddress"),
            WorkstationName = Get("WorkstationName", "Workstation", "CallerComputerName"),
            LogonType = Get("LogonType"), FailureReason = Get("FailureReason", "FailureCode"),
            Status = Get("Status"), SubStatus = Get("SubStatus")
        };
    }
}
