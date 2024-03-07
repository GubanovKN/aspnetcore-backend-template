namespace api.Models.Users;

public class AddRequest
{
    public string? LastName { get; set; }
    public string? FirstName { get; set; }
    public string? MiddleName { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public List<Guid> Roles { get; set; } = [];
}