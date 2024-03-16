using System.Text.Json.Serialization;
using api.Entities;

namespace api.Models.Users;

public class AuthenticateResponse(Guid userId, string jwtToken, string refreshToken)
{
    public Guid Id { get; set; } = userId;
    public string AccessToken { get; set; } = jwtToken;
    public string RefreshToken { get; set; } = refreshToken;
}