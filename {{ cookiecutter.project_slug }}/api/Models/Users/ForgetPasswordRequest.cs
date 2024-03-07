namespace api.Models.Users;

public class ForgetPasswordRequest
{
    public string Username { get; set; } = null!;
    public string Token { get; set; } = null!;
    public string NewPassword { get; set; } = null!;
}