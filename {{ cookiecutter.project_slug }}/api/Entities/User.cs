using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace api.Entities;

public class User
{
    [Key] 
    public Guid Id { get; set; }
    public string? FirstName { get; set; }
    public string? MiddleName { get; set; }
    public string? LastName { get; set; }
    public string? Phone { get; set; }
    public string? Email { get; set; }

    [JsonIgnore]
    [DefaultValue(0)]
    public int CountFailedLogins { get; set; }

    [JsonIgnore]
    [DefaultValue(false)]
    public bool IsDismissed { get; set; }

    [JsonIgnore]
    public string? PasswordHash { get; set; }

    [JsonIgnore]
    public byte[] Salt { get; set; } = null!;

    [JsonIgnore]
    [InverseProperty(nameof(UserRole.User))]
    public List<UserRole> UserRoles { get; set; } = [];

    [JsonIgnore]
    public List<RefreshToken> RefreshTokens { get; set; } = [];
}