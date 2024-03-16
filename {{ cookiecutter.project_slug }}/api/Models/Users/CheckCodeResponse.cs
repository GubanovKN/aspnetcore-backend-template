namespace api.Models.Users;

public class CheckCodeResponse
{
    public string Token { get; set; } = string.Empty;
    public bool Exist { get; set; }
}