using api.Entities;

namespace api.Models.Users;

public class GetByIdResponse
{
    public Guid Id { get; set; }
    public string? FirstName { get; set; }
    public string? MiddleName { get; set; }
    public string? LastName { get; set; }
    public string? Email { get; set; }
    public List<Role?> Roles { get; set; } = [];
    public bool IsDismissed { get; set; }
}