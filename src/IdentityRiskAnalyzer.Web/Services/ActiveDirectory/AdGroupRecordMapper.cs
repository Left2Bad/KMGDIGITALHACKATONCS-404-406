using System.DirectoryServices.Protocols;
using IdentityRiskAnalyzer.Web.Domain.Models;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public sealed class AdGroupRecordMapper(ILogger<AdGroupRecordMapper> logger)
{
    public AdGroupRecord? Map(SearchResultEntry entry, GroupMemberAttributeBatch members)
    {
        var distinguishedName = entry.DistinguishedName;
        var objectGuid = ActiveDirectoryAttributeConverter.ConvertGuid(
            ActiveDirectoryAttributeConverter.GetFirstValue(entry, "objectGUID"));

        if (objectGuid is null)
        {
            logger.LogWarning(
                "Skipping LDAP group entry with missing or malformed objectGUID. DN={DistinguishedName}.",
                distinguishedName);
            return null;
        }

        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            logger.LogWarning("Skipping LDAP group entry with an empty distinguishedName.");
            return null;
        }

        var rawSid = ActiveDirectoryAttributeConverter.GetFirstValue(entry, "objectSid");
        var sid = ActiveDirectoryAttributeConverter.ConvertSid(rawSid);
        if (rawSid is not null && sid is null)
        {
            logger.LogWarning("Malformed objectSid on LDAP group entry. DN={DistinguishedName}.", distinguishedName);
        }

        var rawGroupType = ActiveDirectoryAttributeConverter.GetFirstValue(entry, "groupType");
        var groupType = 0L;
        if (rawGroupType is null || !ActiveDirectoryAttributeConverter.TryConvertInt64(rawGroupType, out groupType))
        {
            logger.LogWarning("Missing or malformed groupType on LDAP group entry. DN={DistinguishedName}.", distinguishedName);
        }

        if (!members.IsComplete || members.IsMalformed)
        {
            logger.LogWarning(
                "LDAP group member list is incomplete. DN={DistinguishedName}.",
                distinguishedName);
        }

        return new AdGroupRecord
        {
            ObjectGuid = objectGuid.Value,
            Sid = sid,
            DistinguishedName = distinguishedName,
            CommonName = ActiveDirectoryAttributeConverter.GetFirstString(entry, "cn"),
            SamAccountName = ActiveDirectoryAttributeConverter.GetFirstString(entry, "sAMAccountName"),
            GroupType = groupType,
            MemberDistinguishedNames = members.Members,
            Description = ActiveDirectoryAttributeConverter.GetFirstString(entry, "description"),
            ManagedBy = ActiveDirectoryAttributeConverter.GetFirstString(entry, "managedBy"),
            MembersComplete = members.IsComplete
        };
    }
}
