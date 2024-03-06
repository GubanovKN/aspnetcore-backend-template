using api.Entities;
using Microsoft.EntityFrameworkCore;

namespace api.Helpers;

public sealed class DataContext : DbContext
{
    private readonly string? _connectionString;
    
    public DbSet<User> Users { get; set; } = null!;
    public DbSet<OAuth> OAuths { get; set; } = null!;
    public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;
    public DbSet<Role> Roles { get; set; } = null!;
    public DbSet<UserRole> UserRoles { get; set; } = null!;

    public DataContext(string? connectionString) : base()
    {
        _connectionString = connectionString;
    }

    public DataContext(DbContextOptions<DataContext> options) : base(options)
    {
        Database.EnsureCreated();
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            if (_connectionString != null)
            {
                optionsBuilder.UseNpgsql(_connectionString);
            }
        }

        base.OnConfiguring(optionsBuilder);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<UserRole>().HasOne(x => x.User).WithMany(x => x.UserRoles).HasForeignKey(x => x.UserId);
        modelBuilder.Entity<UserRole>().HasOne(x => x.Role).WithMany(x => x.UserRoles).HasForeignKey(x => x.RoleId);

        var salt = new Encryption().GetSalt();

        User[] users =
        [
            new User
            {
                Id = Guid.NewGuid(),
                FirstName = "Admin",
                MiddleName = "Admin",
                LastName = "Admin",
                Email = "admin@test.com",
                Salt = salt,
                PasswordHash = Encryption.GetHash("password", salt)
            }
        ];

        Role[] roles =
        [
            new Role { Id = Guid.NewGuid(), Name = "Admin" },
            new Role { Id = Guid.NewGuid(), Name = "User" }
        ];

        UserRole[] userRoles =
        [
            new UserRole
            {
                Id = Guid.NewGuid(),
                UserId = users[0].Id,
                RoleId = roles[0].Id
            }
        ];

        modelBuilder.Entity<User>().HasData(users);
        modelBuilder.Entity<Role>().HasData(roles);
        modelBuilder.Entity<UserRole>().HasData(userRoles);
    }
}