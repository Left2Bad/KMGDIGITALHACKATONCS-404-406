namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public sealed class MemberDnAccumulator
{
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _members = [];

    public int Count => _members.Count;

    public void AddRange(IEnumerable<string> distinguishedNames)
    {
        foreach (var distinguishedName in distinguishedNames)
        {
            if (!string.IsNullOrWhiteSpace(distinguishedName) && _seen.Add(distinguishedName))
            {
                _members.Add(distinguishedName);
            }
        }
    }

    public IReadOnlyList<string> ToReadOnlyList()
    {
        return _members.Count == 0 ? Array.Empty<string>() : Array.AsReadOnly(_members.ToArray());
    }
}
