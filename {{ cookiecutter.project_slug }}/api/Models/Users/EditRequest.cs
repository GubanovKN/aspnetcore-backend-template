namespace api.Models.Users;

public class EditRequest
{
    public Guid Id { get; set; }
    public string? LastName { get; set; }
    public string? FirstName { get; set; }
    public string? MiddleName { get; set; }
    public string Email { get; set; } = string.Empty;
    public string? Password { get; set; }
    public List<Guid> Roles { get; set; } = [];
    public bool IsDismissed { get; set; }
}