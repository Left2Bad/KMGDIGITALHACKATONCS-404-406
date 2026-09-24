using IdentityRiskAnalyzer.Web.Domain.Enums;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public static class ActiveDirectoryGroupTypeHelper
{
    private const uint BuiltinLocalFlag = 0x00000001;
    private const uint GlobalFlag = 0x00000002;
    private const uint DomainLocalFlag = 0x00000004;
    private const uint UniversalFlag = 0x00000008;
    private const uint SecurityEnabledFlag = 0x80000000;

    public static bool IsSecurityGroup(long groupType)
    {
        return (unchecked((uint)groupType) & SecurityEnabledFlag) != 0;
    }

    public static AdGroupScope GetScope(long groupType)
    {
        var flags = unchecked((uint)groupType);
        if ((flags & BuiltinLocalFlag) != 0)
        {
            return AdGroupScope.BuiltinLocal;
        }

        if ((flags & GlobalFlag) != 0)
        {
            return AdGroupScope.Global;
        }

        if ((flags & DomainLocalFlag) != 0)
        {
            return AdGroupScope.DomainLocal;
        }

        if ((flags & UniversalFlag) != 0)
        {
            return AdGroupScope.Universal;
        }

        return AdGroupScope.Unknown;
    }

    public static string Describe(long groupType)
    {
        var category = IsSecurityGroup(groupType) ? "Security" : "Distribution";
        var scope = GetScope(groupType) switch
        {
            AdGroupScope.BuiltinLocal => "Builtin Local",
            AdGroupScope.Global => "Global",
            AdGroupScope.DomainLocal => "Domain Local",
            AdGroupScope.Universal => "Universal",
            _ => "Unknown scope"
        };

        return $"{category} · {scope}";
    }
}
