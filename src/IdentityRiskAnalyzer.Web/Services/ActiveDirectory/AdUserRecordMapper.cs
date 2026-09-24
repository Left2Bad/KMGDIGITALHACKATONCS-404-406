using System.DirectoryServices.Protocols;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public sealed class AdUserRecordMapper(ILogger<AdUserRecordMapper> logger)
{
    public AdUserRecord? Map(SearchResultEntry entry)
    {
        var distinguishedName = entry.DistinguishedName;
        var objectGuid = ActiveDirectoryAttributeConverter.ConvertGuid(
            ActiveDirectoryAttributeConverter.GetFirstValue(entry, "objectGUID"));

        if (objectGuid is null)
        {
            logger.LogWarning(
                "Skipping LDAP user entry with missing or malformed objectGUID. DN={DistinguishedName}.",
                distinguishedName);
            return null;
        }

        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            logger.LogWarning("Skipping LDAP user entry with an empty distinguishedName.");
            return null;
        }

        var rawSid = ActiveDirectoryAttributeConverter.GetFirstValue(entry, "objectSid");
        var sid = ActiveDirectoryAttributeConverter.ConvertSid(rawSid);
        if (rawSid is not null && sid is null)
        {
            logger.LogWarning("Malformed objectSid on LDAP user entry. DN={DistinguishedName}.", distinguishedName);
        }

        var sidHistory = new List<string>();
        foreach (var sidBytes in ActiveDirectoryAttributeConverter.GetMultiValueBytes(entry, "sIDHistory"))
        {
            var historySid = ActiveDirectoryAttributeConverter.ConvertSid(sidBytes);
            if (historySid is null)
            {
                logger.LogWarning("Malformed sIDHistory value on LDAP user entry. DN={DistinguishedName}.", distinguishedName);
                continue;
            }

            sidHistory.Add(historySid);
        }

        var userAccountControl = ReadInt64(entry, "userAccountControl", distinguishedName) ?? 0;

        return new AdUserRecord
        {
            ObjectGuid = objectGuid.Value,
            Sid = sid,
            DistinguishedName = distinguishedName,
            SamAccountName = ActiveDirectoryAttributeConverter.GetFirstString(entry, "sAMAccountName"),
            UserPrincipalName = ActiveDirectoryAttributeConverter.GetFirstString(entry, "userPrincipalName"),
            DisplayName = ActiveDirectoryAttributeConverter.GetFirstString(entry, "displayName"),
            UserAccountControl = userAccountControl,
            ComputedUserAccountControl = ReadInt64(entry, "msDS-User-Account-Control-Computed", distinguishedName),
            LastKnownActivityUtc = ReadFileTime(entry, "lastLogonTimestamp", distinguishedName),
            PasswordLastSetUtc = ReadFileTime(entry, "pwdLastSet", distinguishedName),
            AccountExpiresUtc = ReadFileTime(entry, "accountExpires", distinguishedName),
            LockoutTimeRaw = ReadInt64(entry, "lockoutTime", distinguishedName),
            PrimaryGroupId = ReadInt32(entry, "primaryGroupID", distinguishedName),
            MemberOfDistinguishedNames = ActiveDirectoryAttributeConverter.GetMultiValueStrings(entry, "memberOf"),
            ServicePrincipalNames = ActiveDirectoryAttributeConverter.GetMultiValueStrings(entry, "servicePrincipalName"),
            ManagedBy = ActiveDirectoryAttributeConverter.GetFirstString(entry, "managedBy"),
            Description = ActiveDirectoryAttributeConverter.GetFirstString(entry, "description"),
            SidHistory = sidHistory.AsReadOnly(),
            AllowedToDelegateTo = ActiveDirectoryAttributeConverter.GetMultiValueStrings(entry, "msDS-AllowedToDelegateTo"),
            HasResourceBasedConstrainedDelegation =
                ActiveDirectoryAttributeConverter.HasNonEmptyValue(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity"),
            ObjectClasses = ActiveDirectoryAttributeConverter.GetMultiValueStrings(entry, "objectClass")
        };
    }

    private long? ReadInt64(SearchResultEntry entry, string attributeName, string distinguishedName)
    {
        var rawValue = ActiveDirectoryAttributeConverter.GetFirstValue(entry, attributeName);
        if (rawValue is null)
        {
            if (attributeName == "userAccountControl")
            {
                logger.LogWarning("Missing userAccountControl on LDAP user entry. DN={DistinguishedName}.", distinguishedName);
            }

            return null;
        }

        if (ActiveDirectoryAttributeConverter.TryConvertInt64(rawValue, out var value))
        {
            return value;
        }

        logger.LogWarning(
            "Malformed numeric LDAP attribute {AttributeName} on user entry. DN={DistinguishedName}.",
            attributeName,
            distinguishedName);
        return null;
    }

    private DateTimeOffset? ReadFileTime(SearchResultEntry entry, string attributeName, string distinguishedName)
    {
        var rawValue = ActiveDirectoryAttributeConverter.GetFirstValue(entry, attributeName);
        if (rawValue is null)
        {
            return null;
        }

        if (ActiveDirectoryAttributeConverter.TryConvertFileTime(rawValue, out var value))
        {
            return value;
        }

        logger.LogWarning(
            "Malformed FILETIME LDAP attribute {AttributeName} on user entry. DN={DistinguishedName}.",
            attributeName,
            distinguishedName);
        return null;
    }

    private int? ReadInt32(SearchResultEntry entry, string attributeName, string distinguishedName)
    {
        var value = ReadInt64(entry, attributeName, distinguishedName);
        if (value is null)
        {
            return null;
        }

        if (value < int.MinValue || value > int.MaxValue)
        {
            logger.LogWarning(
                "LDAP attribute {AttributeName} is outside the Int32 range on user entry. DN={DistinguishedName}.",
                attributeName,
                distinguishedName);
            return null;
        }

        return (int)value.Value;
    }
}
