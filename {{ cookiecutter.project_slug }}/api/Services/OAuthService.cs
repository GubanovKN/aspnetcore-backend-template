using api.Authorization;
using api.Entities;
using api.Helpers;
using api.Models.OAuth;
using api.Models.Users;
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2.Responses;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using RestSharp;

namespace api.Services;

public interface IOAuthService
{
    Task<GoogleResponse> GoogleAsync(GoogleRequest model, string ipAddress);
}

public class OAuthService(
    DataContext context,
    IAuthService authService,
    IJwtUtils jwtUtils,
    IUserService userService,
    IOptions<AppSettings> appSettings)
    : IOAuthService
{
    private readonly AppSettings _appSettings = appSettings.Value;

    #region Google

    public async Task<GoogleResponse> GoogleAsync(GoogleRequest model, string ipAddress)
    {
        var tokens = await GoogleTokens(model.Code);
        if (tokens == null) throw new AppException("Invalid code");

        var userInfo = await GoogleInfo(tokens.IdToken);
        var emailNormalize = Normalize.Email(userInfo.Email);

        var existData = context.OAuths.SingleOrDefault(p => p.GoogleId == userInfo.Subject);
        if (existData != null)
        {
            if (tokens.RefreshToken != null && existData.GoogleRefreshToken != tokens.RefreshToken)
            {
                existData.GoogleRefreshToken = tokens.RefreshToken;
                await context.SaveChangesAsync();
            }

            var user = userService.GetById(existData.UserId);

            if (user == null) throw new AppException("User not found");

            if (user.Email != emailNormalize)
            {
                user.Email = emailNormalize;
                await context.SaveChangesAsync();
            }

            var result = authService.Authenticate(new AuthenticateRequest
            {
                Type = "token",
                Username = user.Email,
                Password = jwtUtils.GenerateJwtData(user.Email)
            }, ipAddress);

            return new GoogleResponse(result);
        }
        else
        {
            var result = authService.Register(new RegisterRequest
            {
                Type = "email",
                Email = emailNormalize,
                EmailToken = jwtUtils.GenerateJwtData(emailNormalize),
                FirstName = userInfo.GivenName,
                LastName = userInfo.FamilyName
            }, ipAddress);

            context.OAuths.Add(new OAuth
            {
                GoogleId = userInfo.Subject,
                GoogleRefreshToken = tokens.RefreshToken,
                UserId = result.Id
            });
            await context.SaveChangesAsync();

            return new GoogleResponse(result);
        }
    }

    private async Task<TokenResponse?> GoogleTokens(string code)
    {
        var options = new RestClientOptions("https://oauth2.googleapis.com")
        {
            MaxTimeout = -1
        };
        var client = new RestClient(options);
        var request = new RestRequest("/token", Method.Post);

        request.AddParameter("code", code);
        request.AddParameter("client_id", _appSettings.OAuth.Google.ClientId);
        request.AddParameter("client_secret", _appSettings.OAuth.Google.ClientSecret);
        request.AddParameter("grant_type", "authorization_code");
        request.AddParameter("redirect_uri", _appSettings.OAuth.Google.RedirectURL);
        request.AddParameter("access_type", "offline");

        var response = await client.ExecuteAsync(request, CancellationToken.None);
        if (response.IsSuccessful && !string.IsNullOrEmpty(response.Content))
        {
            return JsonConvert.DeserializeObject<TokenResponse>(response.Content);
        }

        return null;
    }

    private async Task<GoogleJsonWebSignature.Payload> GoogleInfo(string idToken)
    {
        var validationResult = new GoogleJsonWebSignature.ValidationSettings
        {
            Audience = new[] { _appSettings.OAuth.Google.ClientId }
        };

        var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, validationResult);

        return payload;
    }

    #endregion
}