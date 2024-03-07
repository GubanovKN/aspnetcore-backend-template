using System.Text.Json.Serialization;
using api.Entities;

namespace api.Models.Users;

public class AuthenticateResponse
{
    public Guid Id { get; set; }
    public string? FirstName { get; set; } = null!;
    public string? LastName { get; set; } = null!;
    public string? Email { get; set; } = null!;
    public string Token { get; set; }

    public List<Role> Roles { get; set; }

    [JsonIgnore]
    public string RefreshToken { get; set; }


    public AuthenticateResponse(User user, string jwtToken, string refreshToken)
    {
        Id = user.Id;
        FirstName = user.FirstName;
        LastName = user.LastName;
        Email = user.Email;
        Token = jwtToken;
        RefreshToken = refreshToken;
        Roles = new List<Role>();
        foreach(var userRole in user.UserRoles!)
        {
            Roles.Add(userRole.Role!);
        }
    }
}