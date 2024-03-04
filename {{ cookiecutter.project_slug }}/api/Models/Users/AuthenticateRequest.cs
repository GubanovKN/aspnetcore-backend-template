using System.ComponentModel.DataAnnotations;

namespace api.Models.Users;

public class AuthenticateRequest
{
    [Required]
    public string Type { get; set; } = null!;
    [Required]
    public string Username { get; set; } = null!;
    [Required]
    public string Password { get; set; } = null!;
}