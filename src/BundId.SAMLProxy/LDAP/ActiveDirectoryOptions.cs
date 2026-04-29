using System.ComponentModel.DataAnnotations;

namespace JGUZDV.BundId.SAMLProxy.ActiveDirectory;

public class ActiveDirectoryOptions : IValidatableObject
{
    public required string BaseOU { get; set; }

    public string? DomainName { get; set; }
    public string? DomainSite { get; set; }

    public int LdapPort { get; set; } = 636;

    public required string BundIdBPK2Property { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (string.IsNullOrWhiteSpace(BaseOU))
        {
            yield return new ValidationResult("BaseOU is required", [nameof(BaseOU)]);
        }

        if (string.IsNullOrWhiteSpace(BundIdBPK2Property))
        {
            yield return new ValidationResult("BundIdBPK2Property is required", [nameof(BundIdBPK2Property)]);
        }
    }
}
