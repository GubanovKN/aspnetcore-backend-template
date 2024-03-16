using System.Text.Json.Serialization;
using api.Entities;
using api.Models.Users;

namespace api.Models.OAuth;

public class GoogleResponse
{
    public Guid Id { get; set; }
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }


    public GoogleResponse(AuthenticateResponse model)
    {
        Id = model.Id;
        AccessToken = model.AccessToken;
        RefreshToken = model.RefreshToken;
    }
    
    public GoogleResponse(RegisterResponse model)
    {
        Id = model.Id;
        AccessToken = model.AccessToken;
        RefreshToken = model.RefreshToken;
    }
}