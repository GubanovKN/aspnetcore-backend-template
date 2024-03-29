using System.Net.Mail;
using System.Text.RegularExpressions;
using api.Authorization;
using api.Entities;
using api.Helpers;
using api.Models.Users;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace api.Services;

public interface IAuthService
{
    Task<SendCodeResponse> SendCodeByEmail(string email);
    Task<SendCodeResponse> SendCodeByPhone(string phone);
    Task<CheckCodeResponse> CheckCode(string key, string code);
    RegisterResponse Register(RegisterRequest model, string ipAddress);
    AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
    AuthenticateResponse RefreshToken(string? token, string ipAddress);
    void ForgetPassword(ForgetPasswordRequest model);
    void RevokeToken(string token, string ipAddress);
}

public class AuthService(
    DataContext context,
    IUserService userService,
    IJwtUtils jwtUtils,
    ISendMailService sendMailService,
    ISendPhoneService sendPhoneService,
    IDistributedCache distributedCache,
    IOptions<AppSettings> appSettings) : IAuthService
{
    private readonly AppSettings _appSettings = appSettings.Value;

    public async Task<SendCodeResponse> SendCodeByEmail(string email)
    {
        email = Normalize.Email(email);
        var code = new Encryption().GetRandomPassword(6);
        var storageData = await distributedCache.GetStringAsync(email);
        if (storageData != null)
        {
            return new SendCodeResponse
            {
                Repeat = _appSettings.TimeExpireCode,
                Result = false
            };
        }

        await distributedCache.SetStringAsync(email, code, new DistributedCacheEntryOptions
        {
            SlidingExpiration = TimeSpan.FromSeconds(_appSettings.TimeExpireCode)
        });

        sendMailService.Send(email, "Registration", $"Temporary password: <b>{code}</b>");

        return new SendCodeResponse
        {
            Repeat = _appSettings.TimeExpireCode,
            Result = true
        };
    }

    public async Task<SendCodeResponse> SendCodeByPhone(string phone)
    {
        phone = Normalize.Phone(phone);
        var code = new Encryption().GetRandomPassword(6);
        var storageData = await distributedCache.GetStringAsync(phone);
        if (storageData != null)
        {
            return new SendCodeResponse
            {
                Repeat = _appSettings.TimeExpireCode,
                Result = false
            };
        }

        await distributedCache.SetStringAsync(phone, code, new DistributedCacheEntryOptions
        {
            SlidingExpiration = TimeSpan.FromSeconds(_appSettings.TimeExpireCode)
        });
        sendPhoneService.Send(phone, $"Temporary password: {code}");

        return new SendCodeResponse
        {
            Repeat = _appSettings.TimeExpireCode,
            Result = true
        };
    }

    public async Task<CheckCodeResponse> CheckCode(string key, string code)
    {
        string type;
        if (Normalize.CheckPhone(key))
        {
            key = Normalize.Phone(key);
            type = "phone";
        }
        else if (Normalize.CheckEmail(key))
        {
            key = Normalize.Email(key);
            type = "email";
        }
        else
        {
            throw new AppException("Invalid type");
        }

        var storageData = await distributedCache.GetStringAsync(key);

        if (storageData == null || storageData != code)
        {
            throw new AppException("Invalid code");
        }

        await distributedCache.RemoveAsync(key);

        var exist = type switch
        {
            "email" => userService.ExistByEmail(key),
            "phone" => userService.ExistByPhone(key),
            _ => false
        };
        
        return new CheckCodeResponse
        {
            Token = jwtUtils.GenerateJwtData(key),
            Exist = exist
        };
    }

    public RegisterResponse Register(RegisterRequest model, string ipAddress)
    {
        User? user;

        var phoneTokenData = jwtUtils.ValidateJwtData(model.PhoneToken);
        var emailTokenData = jwtUtils.ValidateJwtData(model.EmailToken);

        switch (model.Type)
        {
            case "all":
                if (model.Email == null || model.Phone == null)
                {
                    throw new AppException("Email and phone are required");
                }

                model.Phone = Normalize.Phone(model.Phone);
                model.Email = Normalize.Email(model.Email);

                if (model.Email != emailTokenData || model.Phone != phoneTokenData)
                {
                    throw new AppException("Invalid one or more tokens");
                }

                user = context.Users.AsEnumerable().FirstOrDefault(x =>
                    string.Equals(x.Email, model.Email, StringComparison.CurrentCultureIgnoreCase) ||
                    string.Equals(x.Phone, model.Phone, StringComparison.InvariantCultureIgnoreCase));

                break;
            case "email":
                if (model.Email == null)
                {
                    throw new AppException("Email are required");
                }

                model.Email = Normalize.Email(model.Email);

                if (model.Email != emailTokenData)
                {
                    throw new AppException("Invalid one or more tokens");
                }

                model.Phone = null;

                user = context.Users.AsEnumerable().SingleOrDefault(x =>
                    string.Equals(x.Email, model.Email, StringComparison.CurrentCultureIgnoreCase));

                break;
            case "phone":
                if (model.Phone == null)
                {
                    throw new AppException("Phone are required");
                }

                model.Phone = Normalize.Phone(model.Phone);

                if (model.Phone != phoneTokenData)
                {
                    throw new AppException("Invalid one or more tokens");
                }

                model.Email = null;

                user = context.Users.AsEnumerable().SingleOrDefault(x =>
                    string.Equals(x.Phone, model.Phone, StringComparison.InvariantCultureIgnoreCase));

                break;
            default:
                throw new AppException("Invalid type");
        }


        if (user != null)
        {
            throw new AppException("User already exists");
        }

        var role = context.Roles.FirstOrDefault(p => p.Name == "User");

        if (role == null)
        {
            throw new AppException("Base role not found");
        }

        var salt = new Encryption().GetSalt();

        user = new User
        {
            LastName = model.LastName,
            MiddleName = model.MiddleName,
            FirstName = model.FirstName,
            Phone = model.Phone,
            Email = model.Email,
            Salt = salt,
            PasswordHash = !string.IsNullOrWhiteSpace(model.Password) ? Encryption.GetHash(model.Password, salt) : null
        };

        var result = context.Users.Add(user);
        context.SaveChanges();

        context.UserRoles.Add(new UserRole
        {
            UserId = result.Entity.Id,
            RoleId = role.Id
        });
        context.SaveChanges();

        var jwtToken = jwtUtils.GenerateJwtUser(user);
        var refreshToken = jwtUtils.GenerateRefreshToken(ipAddress);
        refreshToken.UserId = user.Id;
        context.RefreshTokens.Add(refreshToken);
        context.SaveChanges();

        return new RegisterResponse(result.Entity.Id, jwtToken, refreshToken.Token);
    }

    public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
    {
        var user = model.Type switch
        {
            "password" => GetUserPassword(model.Username, model.Password),
            "token" => GetUserToken(model.Username, model.Password),
            _ => throw new AppException("Invalid type")
        };

        if (user.IsDismissed)
            throw new AppException("User is dismissed");

        var jwtToken = jwtUtils.GenerateJwtUser(user);
        var refreshToken = jwtUtils.GenerateRefreshToken(ipAddress);
        user.RefreshTokens.Add(refreshToken);

        RemoveOldRefreshTokens(user);

        context.Update(user);
        context.SaveChanges();

        return new AuthenticateResponse(user.Id, jwtToken, refreshToken.Token);
    }

    private User GetUserPassword(string username, string password)
    {
        User? user = null;

        if (Normalize.CheckEmail(username))
        {
            user = userService.GetByEmail(Normalize.Email(username));
        }
        else if (Normalize.CheckPhone(username))
        {
            user = userService.GetByPhone(Normalize.Phone(username));
        }

        if (user == null)
        {
            throw new AppException("Incorrect username or password");
        }

        if (user.PasswordHash == null)
        {
            throw new AppException("Access for this type denied");
        }

        if (Encryption.GetHash(password, user.Salt) == user.PasswordHash)
        {
            return user;
        }

        user.CountFailedLogins += 1;
        context.Update(user);
        context.SaveChanges();

        if (user.CountFailedLogins < 3)
        {
            throw new AppException("Incorrect username or password");
        }

        user.IsDismissed = true;
        context.Update(user);
        context.SaveChanges();

        return user;
    }

    private User GetUserToken(string username, string token)
    {
        User? user = null;

        if (Normalize.CheckEmail(username))
        {
            user = userService.GetByEmail(Normalize.Email(username));
        }
        else if (Normalize.CheckPhone(username))
        {
            user = userService.GetByPhone(Normalize.Phone(username));
        }

        if (user == null)
        {
            throw new AppException("Incorrect username or code");
        }

        var tokenData = jwtUtils.ValidateJwtData(token);
        if (tokenData != null && (tokenData == user.Email || tokenData == user.Phone))
        {
            return user;
        }

        user.CountFailedLogins += 1;
        context.Update(user);
        context.SaveChanges();

        if (user.CountFailedLogins < 3)
        {
            throw new AppException("Incorrect username or code");
        }

        user.IsDismissed = true;
        context.Update(user);
        context.SaveChanges();

        return user;
    }

    public void ForgetPassword(ForgetPasswordRequest model)
    {
        User? user = null;

        if (Normalize.CheckEmail(model.Username))
        {
            user = userService.GetByEmail(Normalize.Email(model.Username));
        }
        else if (Normalize.CheckPhone(model.Username))
        {
            user = userService.GetByPhone(Normalize.Phone(model.Username));
        }

        if (user == null)
        {
            throw new AppException("User not found");
        }

        if (user.PasswordHash == null)
        {
            throw new AppException("Access denied");
        }

        var tokenData = jwtUtils.ValidateJwtData(model.Token);
        if (tokenData == null || (tokenData != user.Email && tokenData != user.Phone))
        {
            throw new AppException("Invalid token");
        }

        user.PasswordHash = Encryption.GetHash(model.NewPassword, user.Salt);
        context.Update(user);
        context.SaveChanges();
    }

    public AuthenticateResponse RefreshToken(string? token, string ipAddress)
    {
        var user = GetUserByRefreshToken(token);
        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

        if (refreshToken.IsRevoked)
        {
            RevokeDescendantRefreshTokens(refreshToken, user, ipAddress,
                $"Attempted reuse of revoked ancestor token: {token}");
            context.Update(user);
            context.SaveChanges();
        }

        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        var newRefreshToken = RotateRefreshToken(refreshToken, ipAddress);
        user.RefreshTokens.Add(newRefreshToken);

        RemoveOldRefreshTokens(user);

        context.Update(user);
        context.SaveChanges();

        var jwtToken = jwtUtils.GenerateJwtUser(user);

        return new AuthenticateResponse(user.Id, jwtToken, newRefreshToken.Token);
    }

    public void RevokeToken(string token, string? ipAddress)
    {
        var user = GetUserByRefreshToken(token);
        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        RevokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
        context.Update(user);
        context.SaveChanges();
    }

    private User GetUserByRefreshToken(string? token)
    {
        var refreshToken = context.RefreshTokens.SingleOrDefault(p => p.Token == token);

        if (refreshToken == null) throw new AppException("Incorrect token");

        var user = userService.GetById(refreshToken.UserId);

        if (user == null)
            throw new AppException("User not found");

        return user;
    }

    private RefreshToken RotateRefreshToken(RefreshToken refreshToken, string ipAddress)
    {
        var newRefreshToken = jwtUtils.GenerateRefreshToken(ipAddress);
        RevokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
        return newRefreshToken;
    }

    private void RemoveOldRefreshTokens(User user)
    {
        user.RefreshTokens.RemoveAll(x =>
            !x.IsActive &&
            x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
    }

    private void RevokeDescendantRefreshTokens(RefreshToken refreshToken, User user, string ipAddress, string reason)
    {
        if (string.IsNullOrEmpty(refreshToken.ReplacedByToken)) return;

        var childToken = user.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
        if (childToken == null) return;
        if (childToken.IsActive)
            RevokeRefreshToken(childToken, ipAddress, reason);
        else
            RevokeDescendantRefreshTokens(childToken, user, ipAddress, reason);
    }

    private void RevokeRefreshToken(RefreshToken token, string? ipAddress, string? reason = null,
        string? replacedByToken = null)
    {
        token.Revoked = DateTime.UtcNow;
        token.RevokedByIp = ipAddress;
        token.ReasonRevoked = reason;
        token.ReplacedByToken = replacedByToken;
    }
}