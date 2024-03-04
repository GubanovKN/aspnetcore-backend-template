using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using api.Entities;

namespace api.Models.Users;

public class RegisterResponse(User user, string jwtToken, string refreshToken, Role role)
{
    public Guid Id { get; set; } = user.Id;
    public string? FirstName { get; set; } = user.FirstName;
    public string? LastName { get; set; } = user.LastName;
    public string? Email { get; set; } = user.Email;
    public string Token { get; set; } = jwtToken;

    public List<Role> Roles { get; set; } = [role];

    [JsonIgnore]
    public string RefreshToken { get; set; } = refreshToken;
}