using System.Net.Mail;
using api.Authorization;
using api.Entities;
using api.Helpers;
using api.Models.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace api.Services;

public interface IUserService
{
    void Register(RegisterRequest model);
    AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
    AuthenticateResponse RefreshToken(string? token, string ipAddress);
    void ForgetPassword(ForgetPasswordRequest model);
    void RevokeToken(string token, string ipAddress);
    User GetById(Guid id);
    User GetByEmail(string email);
    IEnumerable<User> GetAll();
    void Add(AddRequest model);
    void Edit(EditRequest model);
}

public class UserService(
    DataContext context,
    IJwtUtils jwtUtils,
    ISendMailService sendMailService,
    IOptions<AppSettings> appSettings)
    : IUserService
{
    private readonly DataContext _context = context;
    private readonly ISendMailService _sendMailService = sendMailService;
    private readonly AppSettings _appSettings = appSettings.Value;

    public void Register(RegisterRequest model)
    {
        var user = _context.Users.AsEnumerable().SingleOrDefault(x =>
            string.Equals(x.Email, model.Email, StringComparison.CurrentCultureIgnoreCase));
        if (user == null)
        {
            var role = _context.Roles.FirstOrDefault(p=>p.Name == "User");

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
                    var result = _context.Users.Add(user);
                    _context.SaveChanges();
                
                    _context.UserRoles.Add(new UserRole
                    {
                        UserId = result.Entity.Id,
                        RoleId = role.Id
                    });

                    _context.SaveChanges();

                    _sendMailService.Send(model.Email, "Регистрация", $"Ваш временный пароль: <b>{tempPass}</b>");
                }
                catch (SmtpException)
                {
                    throw new AppException("Не удалось отправить временный пароль");
                }
            }
            else
            {
                throw new AppException("Базовая роль не найдена");
            }
        }
        else
        {
            throw new AppException("Пользователь с таким Email уже существует");
        }
    }

    public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
    {
        var user = GetByEmail(model.Email);

        if (user == null || (Encryption.GetHash(model.Password, user.Salt) != user.PasswordHash && !user.IsDismissed))
        {
            if (user == null) throw new AppException("Неверное имя пользователя или пароль");
            
            user.CountFailedLogins += 1;
            _context.Update(user);
            _context.SaveChanges();
            
            if (user.CountFailedLogins < 3) throw new AppException("Неверное имя пользователя или пароль");
            
            user.IsDismissed = true;
            _context.Update(user);
            _context.SaveChanges();

            throw new AppException("Неверное имя пользователя или пароль");
        }

        if (user.IsDismissed)
            throw new AppException("Пользователь заблокирован, для восстановления необходимо нажать забыли пароль");

        var jwtToken = jwtUtils.GenerateJwtToken(user);
        var refreshToken = jwtUtils.GenerateRefreshToken(ipAddress);
        user.RefreshTokens.Add(refreshToken);

        RemoveOldRefreshTokens(user);

        _context.Update(user);
        _context.SaveChanges();

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
            _context.Update(user);
            _context.SaveChanges();
        }

        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        var newRefreshToken = RotateRefreshToken(refreshToken, ipAddress);
        user.RefreshTokens.Add(newRefreshToken);

        RemoveOldRefreshTokens(user);

        _context.Update(user);
        _context.SaveChanges();

        var jwtToken = jwtUtils.GenerateJwtToken(user);

        return new AuthenticateResponse(user, jwtToken, newRefreshToken.Token);
    }

    public void ForgetPassword(ForgetPasswordRequest model)
    {
        var user = _context.Users.AsEnumerable().SingleOrDefault(x =>
            string.Equals(x.Email, model.Email, StringComparison.CurrentCultureIgnoreCase));
        if (user == null)
            throw new AppException("Пользователь с таким Email не найден");

        var tempPass = new Encryption().GetRandomPassword(6);

        try
        {
            _sendMailService.Send(model.Email, "Восстановление пароля", $"Ваш временный пароль: <b>{tempPass}</b>");

            user.PasswordHash = Encryption.GetHash(tempPass, user.Salt);
            _context.Update(user);
            _context.SaveChanges();
        }
        catch (SmtpException)
        {
            throw new AppException("Упс... Мы не смогли отправить временный пароль(");
        }
    }

    public void RevokeToken(string token, string? ipAddress)
    {
        var user = GetUserByRefreshToken(token);
        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        RevokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
        _context.Update(user);
        _context.SaveChanges();
    }

    public User GetById(Guid id)
    {
        var user = _context.Users.SingleOrDefault(p => p.Id == id);
        if (user != null)
        {
            var refreshTokens = _context.RefreshTokens
                .Where(p => p.UserId == user.Id).ToList();
            user.RefreshTokens = refreshTokens;

            var roles = _context.UserRoles
                .Where(p => p.UserId == user.Id).Include(p => p.Role).ToList();
            user.UserRoles = roles;
        }
        else
        {
            throw new AppException("Пользователь не найден");
        }

        return user;
    }

    public User GetByEmail(string email)
    {
        var user = _context.Users.AsEnumerable().SingleOrDefault(p =>
            string.Equals(p.Email, email, StringComparison.CurrentCultureIgnoreCase));
        if (user != null)
        {
            var refreshTokens = _context.RefreshTokens
                .Where(p => p.UserId == user.Id).ToList();
            user.RefreshTokens = refreshTokens;

            var roles = _context.UserRoles
                .Where(p => p.UserId == user.Id).Include(p => p.Role).ToList();
            user.UserRoles = roles;
        }
        else
        {
            throw new AppException("Пользователь не найден");
        }

        return user;
    }

    public IEnumerable<User> GetAll()
    {
        return _context.Users;
    }

    public void Add(AddRequest model)
    {
        if (!_context.Users.AsEnumerable().Any(p =>
                string.Equals(p.Email, model.Email, StringComparison.CurrentCultureIgnoreCase)))
        {
            var salt = new Encryption().GetSalt();

            var user = _context.Users.Add(new User
            {
                LastName = model.LastName,
                FirstName = model.FirstName,
                MiddleName = model.MiddleName,
                Email = model.Email,
                Salt = salt,
                PasswordHash = Encryption.GetHash(model.Password, salt),
            });
            _context.SaveChanges();

            foreach (var t in model.Roles)
            {
                _context.UserRoles.Add(new UserRole
                {
                    RoleId = t,
                    UserId = user.Entity.Id
                });

                _context.SaveChanges();
            }
        }
        else
        {
            throw new AppException("Пользователь с таким логином уже существует");
        }
    }

    public void Edit(EditRequest model)
    {
        var user = GetById(model.Id);
        if (!string.Equals(user.Email, model.Email, StringComparison.CurrentCultureIgnoreCase))
        {
            if (_context.Users.AsEnumerable().Any(p =>
                    string.Equals(p.Email, model.Email, StringComparison.CurrentCultureIgnoreCase)))
            {
                throw new AppException("Пользователь с таким логином уже существует");
            }
        }

        user.Email = model.Email;
        user.LastName = model.LastName;
        user.FirstName = model.FirstName;
        user.MiddleName = model.MiddleName;

        if (!string.IsNullOrWhiteSpace(model.Password))
        {
            user.PasswordHash = Encryption.GetHash(model.Password, user.Salt);
        }

        user.UserRoles.Clear();

        if (model.Roles != null)
        {
            foreach (var t in model.Roles)
            {
                user.UserRoles.Add(new UserRole
                {
                    RoleId = t,
                    UserId = user.Id
                });
            }
        }

        user.IsDismissed = model.IsDismissed;

        _context.Update(user);
        _context.SaveChanges();
    }

    private User GetUserByRefreshToken(string? token)
    {
        var refreshToken = _context.RefreshTokens.SingleOrDefault(p => p.Token == token);

        if (refreshToken == null) throw new AppException("Неправильный ключ");

        var user = GetById(refreshToken.UserId);

        if (user == null)
            throw new AppException("Пользователь не найден");

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