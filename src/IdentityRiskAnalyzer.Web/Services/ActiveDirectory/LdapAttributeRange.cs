namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public readonly record struct LdapAttributeRange(long Start, long? End, bool IsFinal)
{
    public long? NextStart => IsFinal || End is null || End == long.MaxValue ? null : End + 1;
}
