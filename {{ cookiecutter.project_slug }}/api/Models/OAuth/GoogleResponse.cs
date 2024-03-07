using System.Text.Json.Serialization;
using api.Entities;
using api.Models.Users;

namespace api.Models.OAuth;

public class GoogleResponse
{
    public Guid Id { get; set; }
    public string? FirstName { get; set; } = null!;
    public string? LastName { get; set; } = null!;
    public string? Email { get; set; } = null!;
    public string Token { get; set; }

    public List<Role> Roles { get; set; }

    [JsonIgnore]
    public string RefreshToken { get; set; }


    public GoogleResponse(AuthenticateResponse model)
    {
        Id = model.Id;
        FirstName = model.FirstName;
        LastName = model.LastName;
        Email = model.Email;
        Token = model.Token;
        RefreshToken = model.RefreshToken;
        Roles = model.Roles;
    }
    
    public GoogleResponse(RegisterResponse model)
    {
        Id = model.Id;
        FirstName = model.FirstName;
        LastName = model.LastName;
        Email = model.Email;
        Token = model.Token;
        RefreshToken = model.RefreshToken;
        Roles = model.Roles;
    }
}