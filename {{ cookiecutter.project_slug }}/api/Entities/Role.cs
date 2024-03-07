using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace api.Entities;

public class Role
{
    [Key] 
    public Guid Id { get; set; }

    public string? Name { get; set; }

    [JsonIgnore]
    [InverseProperty(nameof(UserRole.Role))]
    public List<UserRole>? UserRoles { get; set; }
}