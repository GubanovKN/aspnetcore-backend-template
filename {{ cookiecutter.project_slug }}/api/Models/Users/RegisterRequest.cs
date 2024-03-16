using System.ComponentModel.DataAnnotations;

namespace api.Models.Users;

public class RegisterRequest
{
    [Required]
    public string Type { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public string FirstName { get; set; } = null!;
    public string? MiddleName { get; set; }
    public int? Sex { get; set; }
    public string? Email { get; set; }
    public string? EmailToken { get; set; }
    public string? Phone { get; set; }
    public string? PhoneToken { get; set; }
    public string? Password { get; set; }
}