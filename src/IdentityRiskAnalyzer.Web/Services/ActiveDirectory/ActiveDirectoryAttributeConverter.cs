using System.Globalization;
using System.Security.Principal;
using System.Text;
using System.DirectoryServices.Protocols;

namespace IdentityRiskAnalyzer.Web.Services.ActiveDirectory;

public static class ActiveDirectoryAttributeConverter
{
    private static readonly long MaximumFileTime =
        DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc).ToFileTimeUtc();

    public static Guid? ConvertGuid(object? value)
    {
        return value is byte[] { Length: 16 } bytes ? new Guid(bytes) : null;
    }

    public static string? ConvertSid(object? value)
    {
        if (!OperatingSystem.IsWindows() || value is not byte[] bytes || bytes.Length == 0)
        {
            return null;
        }

        try
        {
            return new SecurityIdentifier(bytes, 0).Value;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
    }

    public static DateTimeOffset? ConvertFileTime(object? value)
    {
        return TryConvertFileTime(value, out var result) ? result : null;
    }

    public static bool TryConvertFileTime(object? value, out DateTimeOffset? result)
    {
        result = null;
        if (value is null)
        {
            return true;
        }

        if (!TryConvertInt64(value, out var fileTime))
        {
            return false;
        }

        // AD uses zero and Int64.MaxValue to mean that an account has no expiration.
        if (fileTime == 0 || fileTime == long.MaxValue)
        {
            return true;
        }

        if (fileTime < 0 || fileTime >= MaximumFileTime)
        {
            return false;
        }

        try
        {
            result = new DateTimeOffset(DateTime.FromFileTimeUtc(fileTime), TimeSpan.Zero);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    public static bool TryConvertInt64(object? value, out long result)
    {
        switch (value)
        {
            case long number:
                result = number;
                return true;
            case int number:
                result = number;
                return true;
            case short number:
                result = number;
                return true;
            case byte number:
                result = number;
                return true;
            case uint number:
                result = number;
                return true;
            case ulong number when number <= long.MaxValue:
                result = (long)number;
                return true;
            case string text:
                return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out result);
            default:
                result = default;
                return false;
        }
    }

    public static IReadOnlyList<string> ConvertStringValues(IEnumerable<object?>? values)
    {
        if (values is null)
        {
            return Array.Empty<string>();
        }

        var converted = values
            .Select(ConvertStringValue)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .ToArray();

        return converted.Length == 0 ? Array.Empty<string>() : Array.AsReadOnly(converted);
    }

    public static IReadOnlyList<string> GetMultiValueStrings(SearchResultEntry entry, string attributeName)
    {
        return ConvertStringValues(GetAttributeValues(entry, attributeName));
    }

    public static IReadOnlyList<string> GetAttributeNames(SearchResultEntry entry)
    {
        return entry.Attributes.AttributeNames.Cast<string>().ToArray();
    }

    public static IReadOnlyList<byte[]> GetMultiValueBytes(SearchResultEntry entry, string attributeName)
    {
        var values = GetAttributeValues(entry, attributeName)
            .Select(value => value as byte[] ?? Array.Empty<byte>())
            .ToArray();

        return values.Length == 0 ? Array.Empty<byte[]>() : Array.AsReadOnly(values);
    }

    public static object? GetFirstValue(SearchResultEntry entry, string attributeName)
    {
        var values = GetAttributeValues(entry, attributeName);
        return values.Count == 0 ? null : values[0];
    }

    public static string? GetFirstString(SearchResultEntry entry, string attributeName)
    {
        return ConvertStringValues(GetAttributeValues(entry, attributeName)).FirstOrDefault();
    }

    public static bool HasNonEmptyValue(SearchResultEntry entry, string attributeName)
    {
        return GetAttributeValues(entry, attributeName).Any(value => value switch
        {
            byte[] bytes => bytes.Length > 0,
            string text => !string.IsNullOrWhiteSpace(text),
            _ => value is not null
        });
    }

    private static IReadOnlyList<object?> GetAttributeValues(SearchResultEntry entry, string attributeName)
    {
        if (!entry.Attributes.Contains(attributeName))
        {
            return Array.Empty<object?>();
        }

        var attribute = entry.Attributes[attributeName];
        var values = new object?[attribute.Count];
        for (var index = 0; index < attribute.Count; index++)
        {
            values[index] = attribute[index];
        }

        return values;
    }

    private static string? ConvertStringValue(object? value)
    {
        return value switch
        {
            string text => text,
            byte[] bytes => Encoding.UTF8.GetString(bytes),
            _ => null
        };
    }
}
