namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public sealed class LdapRangeProgressGuard
{
    private readonly HashSet<long> _requestedStarts = [];

    public bool TryRegisterRequest(long start)
    {
        return start >= 0 && _requestedStarts.Add(start);
    }

    public static bool Advances(long currentStart, long? nextStart)
    {
        return nextStart is long next && next > currentStart;
    }
}
