namespace api.Models.Users;

public class CheckCodeRequest
{
    public string Key { get; set; } = null!;
    public string Code { get; set; } = null!;
}