using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using api.Entities;
using api.Helpers;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace api.Authorization;

public interface IJwtUtils
{
    public string GenerateJwtToken(User user);
    public Guid? ValidateJwtToken(string? token);
    public RefreshToken GenerateRefreshToken(string ipAddress);
}

public class JwtUtils(
    DataContext context,
    IOptions<AppSettings> appSettings) : IJwtUtils
{
    private readonly DataContext _context = context;
    private readonly AppSettings _appSettings = appSettings.Value;

    public string GenerateJwtToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("id", user.Id.ToString()) }),
            Expires = DateTime.UtcNow.AddDays(1),
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public Guid? ValidateJwtToken(string? token)
    {
        if (token == null)
            return null;

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var userId = Guid.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

            return userId;
        }
        catch
        {
            return null;
        }
    }

    public RefreshToken GenerateRefreshToken(string ipAddress)
    {
        var refreshToken = new RefreshToken
        {
            Token = GetUniqueToken(),
            Expires = DateTime.UtcNow.AddDays(30),
            Created = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };

        return refreshToken;

        string GetUniqueToken()
        {
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            var tokenIsUnique = !_context.RefreshTokens.Any(u => u.Token == token);

            return !tokenIsUnique ? GetUniqueToken() : token;
        }
    }
}