using System.ComponentModel.DataAnnotations;

namespace IdentityRiskAnalyzer.Web.Options;

public sealed class ActiveDirectoryOptions : IValidatableObject
{
    public const string SectionName = "ActiveDirectory";

    [Required]
    public string Server { get; set; } = string.Empty;

    [Range(1, 65535)]
    public int Port { get; set; } = 389;

    public bool UseSsl { get; set; }

    [Required]
    public string BaseDn { get; set; } = string.Empty;

    public string? Username { get; set; }

    public string? Password { get; set; }

    [Range(1, int.MaxValue)]
    public int ConnectTimeoutSeconds { get; set; } = 10;

    [Range(1, 1000)]
    public int PageSize { get; set; } = 500;

    public bool CredentialsConfigured =>
        !string.IsNullOrWhiteSpace(Username) && !string.IsNullOrWhiteSpace(Password);

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        var hasUsername = !string.IsNullOrWhiteSpace(Username);
        var hasPassword = !string.IsNullOrWhiteSpace(Password);

        if (hasUsername != hasPassword)
        {
            yield return new ValidationResult(
                "Both Active Directory username and password must be configured together.",
                [nameof(Username), nameof(Password)]);
        }
    }
}
