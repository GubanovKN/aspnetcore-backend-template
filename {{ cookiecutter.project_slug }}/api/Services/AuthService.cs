using System.Net.Mail;
using api.Authorization;
using api.Entities;
using api.Helpers;
using api.Models.Users;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace api.Services;

public interface IAuthService
{
    void Register(RegisterRequest model);
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
    IDistributedCache distributedCache,
    IOptions<AppSettings> appSettings) : IAuthService
{
    private readonly AppSettings _appSettings = appSettings.Value;

    public void Register(RegisterRequest model)
    {
        var user = context.Users.AsEnumerable().SingleOrDefault(x =>
            string.Equals(x.Email, model.Email, StringComparison.CurrentCultureIgnoreCase));
        if (user == null)
        {
            var role = context.Roles.FirstOrDefault(p => p.Name == "User");

            if (role != null)
            {
                var tempPass = new Encryption().GetRandomPassword(6);

                try
                {
                    var salt = new Encryption().GetSalt();

                    user = new User
                    {
                        LastName = model.LastName,
                        MiddleName = model.MiddleName,
                        FirstName = model.FirstName,
                        Email = model.Email,
                        Salt = salt,
                        PasswordHash = Encryption.GetHash(tempPass, salt)
                    };
                    var result = context.Users.Add(user);
                    context.SaveChanges();

                    context.UserRoles.Add(new UserRole
                    {
                        UserId = result.Entity.Id,
                        RoleId = role.Id
                    });

                    context.SaveChanges();

                    sendMailService.Send(model.Email, "Registration", $"Temporary password: <b>{tempPass}</b>");
                }
                catch (SmtpException)
                {
                    throw new AppException("Sorry, something went wrong. Please try again later.");
                }
            }
            else
            {
                throw new AppException("Base role not found");
            }
        }
        else
        {
            throw new AppException("User with this email already exists");
        }
    }

    public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
    {
        var user = userService.GetByEmail(model.Email);

        if (user == null || (Encryption.GetHash(model.Password, user.Salt) != user.PasswordHash && !user.IsDismissed))
        {
            if (user == null) throw new AppException("Inccorrect username or password");

            user.CountFailedLogins += 1;
            context.Update(user);
            context.SaveChanges();

            if (user.CountFailedLogins < 3) throw new AppException("Inccorrect username or password");

            user.IsDismissed = true;
            context.Update(user);
            context.SaveChanges();

            throw new AppException("Inccorrect username or password");
        }

        if (user.IsDismissed)
            throw new AppException("User is dismissed");

        var jwtToken = jwtUtils.GenerateJwtToken(user);
        var refreshToken = jwtUtils.GenerateRefreshToken(ipAddress);
        user.RefreshTokens.Add(refreshToken);

        RemoveOldRefreshTokens(user);

        context.Update(user);
        context.SaveChanges();

        return new AuthenticateResponse(user, jwtToken, refreshToken.Token);
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

        var jwtToken = jwtUtils.GenerateJwtToken(user);

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
}