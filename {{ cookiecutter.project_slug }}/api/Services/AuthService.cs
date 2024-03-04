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
    Task<string> CheckCode(string key, string code);
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

    private const string regexPhone = @"^([\+]?[1-9]{1})[1-9][0-9]{9}$";

    public async Task<SendCodeResponse> SendCodeByEmail(string email)
    {
        email = EmailNormalize(email);
        var code = new Encryption().GetRandomPassword(6);
        var storageData = await distributedCache.GetStringAsync(email);
        if (storageData != null)
        {
            await distributedCache.RefreshAsync(email);

            return new SendCodeResponse
            {
                Repeat = 120,
                Result = false
            };
        }

        await distributedCache.SetStringAsync(email, code, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(120)
        });
        sendMailService.Send(email, "Registration", $"Temporary password: <b>{code}</b>");

        return new SendCodeResponse
        {
            Repeat = 120,
            Result = true
        };
    }

    public async Task<SendCodeResponse> SendCodeByPhone(string phone)
    {
        phone = PhoneNormalize(phone);
        var code = new Encryption().GetRandomPassword(6);
        var storageData = await distributedCache.GetStringAsync(phone);
        if (storageData != null)
        {
            await distributedCache.RefreshAsync(phone);

            return new SendCodeResponse
            {
                Repeat = 120,
                Result = false
            };
        }

        await distributedCache.SetStringAsync(phone, code, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(120)
        });
        sendPhoneService.Send(phone, $"Temporary password: {code}");

        return new SendCodeResponse
        {
            Repeat = 120,
            Result = true
        };
    }

    public async Task<string> CheckCode(string key, string code)
    {
        if (CheckPhone(key))
        {
            key = PhoneNormalize(key);
        }
        else if (CheckEmail(key))
        {
            key = EmailNormalize(key);
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
        return jwtUtils.GenerateJwtData(key);
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

                model.Phone = PhoneNormalize(model.Phone);
                model.Email = EmailNormalize(model.Email);

                if (model.Email != emailTokenData || model.Phone != phoneTokenData)
                {
                    throw new AppException("Invalid one or more tokens");
                }

                user = context.Users.AsEnumerable().SingleOrDefault(x =>
                    string.Equals(x.Email, model.Email, StringComparison.CurrentCultureIgnoreCase) ||
                    string.Equals(x.Phone, model.Phone, StringComparison.InvariantCultureIgnoreCase));

                break;
            case "email":
                if (model.Email == null)
                {
                    throw new AppException("Email are required");
                }

                model.Email = EmailNormalize(model.Email);

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

                model.Phone = PhoneNormalize(model.Phone);

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

        return new RegisterResponse(user, jwtToken, refreshToken.Token, role);
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

        return new AuthenticateResponse(user, jwtToken, refreshToken.Token);
    }

    private User GetUserPassword(string username, string password)
    {
        User? user = null;

        if (CheckEmail(username))
        {
            user = userService.GetByEmail(EmailNormalize(username));
        }
        else if (CheckPhone(username))
        {
            user = userService.GetByPhone(PhoneNormalize(username));
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

        if (CheckEmail(username))
        {
            user = userService.GetByEmail(EmailNormalize(username));
        }
        else if (CheckPhone(username))
        {
            user = userService.GetByPhone(PhoneNormalize(username));
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

        return new AuthenticateResponse(user, jwtToken, newRefreshToken.Token);
    }

    public void ForgetPassword(ForgetPasswordRequest model)
    {
        var user = context.Users.AsEnumerable().SingleOrDefault(x =>
            string.Equals(x.Email, model.Email, StringComparison.CurrentCultureIgnoreCase));
        if (user == null)
            throw new AppException("User not found");

        var tempPass = new Encryption().GetRandomPassword(6);

        try
        {
            sendMailService.Send(model.Email, "Recovery password", $"Temporary password: <b>{tempPass}</b>");

            user.PasswordHash = Encryption.GetHash(tempPass, user.Salt);
            context.Update(user);
            context.SaveChanges();
        }
        catch (SmtpException)
        {
            throw new AppException("Sorry, something went wrong. Please try again later.");
        }
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

    private string EmailNormalize(string email)
    {
        if (!CheckEmail(email))
        {
            throw new AppException("Invalid email");
        }

        return email.ToLower();
    }

    private bool CheckEmail(string email)
    {
        var trimmedEmail = email.Trim();

        if (trimmedEmail.EndsWith('.'))
        {
            return false;
        }

        try
        {
            var addr = new MailAddress(email);
            return addr.Address == trimmedEmail;
        }
        catch
        {
            return false;
        }
    }

    private string PhoneNormalize(string phone)
    {
        if (!CheckPhone(phone))
        {
            throw new AppException("Invalid phone");
        }

        var regex = new Regex(@"[^\d]");
        phone = regex.Replace(phone, "");
        const string format = "#-###-###-####";
        phone = Convert.ToInt64(phone).ToString(format);
        return phone;
    }

    private bool CheckPhone(string phone)
    {
        return !string.IsNullOrEmpty(phone) && Regex.IsMatch(phone, regexPhone);
    }
}