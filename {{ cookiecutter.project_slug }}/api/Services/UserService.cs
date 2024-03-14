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
    bool ExistByEmail(string email);
    bool ExistByPhone(string phone);
    User GetById(Guid id);
    User GetByEmail(string email);
    User GetByPhone(string phone);
    IEnumerable<User> GetAll();
    void Add(AddRequest model);
    void Edit(EditRequest model);
}

public class UserService(DataContext context) : IUserService
{
    public bool ExistByEmail(string email)
    {
        return context.Users.Any(p => p.Email == email);
    }

    public bool ExistByPhone(string phone)
    {
        return context.Users.Any(p => p.Phone == phone);
    }

    public User GetById(Guid id)
    {
        var user = context.Users.SingleOrDefault(p => p.Id == id);
        if (user != null)
        {
            var refreshTokens = context.RefreshTokens
                .Where(p => p.UserId == user.Id).ToList();
            user.RefreshTokens = refreshTokens;

            var roles = context.UserRoles
                .Where(p => p.UserId == user.Id).Include(p => p.Role).ToList();
            user.UserRoles = roles;
        }
        else
        {
            throw new AppException("User not found");
        }

        return user;
    }

    public User GetByEmail(string email)
    {
        var user = context.Users.AsEnumerable().SingleOrDefault(p =>
            string.Equals(p.Email, email, StringComparison.CurrentCultureIgnoreCase));
        if (user != null)
        {
            var refreshTokens = context.RefreshTokens
                .Where(p => p.UserId == user.Id).ToList();
            user.RefreshTokens = refreshTokens;

            var roles = context.UserRoles
                .Where(p => p.UserId == user.Id).Include(p => p.Role).ToList();
            user.UserRoles = roles;
        }
        else
        {
            throw new AppException("User not found");
        }

        return user;
    }

    public User GetByPhone(string phone)
    {
        var user = context.Users.AsEnumerable().SingleOrDefault(p =>
            string.Equals(p.Phone, phone, StringComparison.CurrentCultureIgnoreCase));
        if (user != null)
        {
            var refreshTokens = context.RefreshTokens
                .Where(p => p.UserId == user.Id).ToList();
            user.RefreshTokens = refreshTokens;

            var roles = context.UserRoles
                .Where(p => p.UserId == user.Id).Include(p => p.Role).ToList();
            user.UserRoles = roles;
        }
        else
        {
            throw new AppException("User not found");
        }

        return user;
    }

    public IEnumerable<User> GetAll()
    {
        return context.Users;
    }

    public void Add(AddRequest model)
    {
        if (!context.Users.AsEnumerable().Any(p =>
                string.Equals(p.Email, model.Email, StringComparison.CurrentCultureIgnoreCase)))
        {
            var salt = new Encryption().GetSalt();

            var user = context.Users.Add(new User
            {
                LastName = model.LastName,
                FirstName = model.FirstName,
                MiddleName = model.MiddleName,
                Email = model.Email,
                Salt = salt,
                PasswordHash = Encryption.GetHash(model.Password, salt),
            });
            context.SaveChanges();

            foreach (var t in model.Roles)
            {
                context.UserRoles.Add(new UserRole
                {
                    RoleId = t,
                    UserId = user.Entity.Id
                });

                context.SaveChanges();
            }
        }
        else
        {
            throw new AppException("User with this email already exists");
        }
    }

    public void Edit(EditRequest model)
    {
        var user = GetById(model.Id);
        if (!string.Equals(user.Email, model.Email, StringComparison.CurrentCultureIgnoreCase))
        {
            if (context.Users.AsEnumerable().Any(p =>
                    string.Equals(p.Email, model.Email, StringComparison.CurrentCultureIgnoreCase)))
            {
                throw new AppException("User with this email already exists");
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

        context.Update(user);
        context.SaveChanges();
    }
}