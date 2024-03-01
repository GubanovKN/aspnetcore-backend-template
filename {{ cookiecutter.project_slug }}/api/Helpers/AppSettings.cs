namespace api.Helpers;

public class AppSettings
{
    public string Secret { get; set; } = string.Empty;
    public int RefreshTokenTTL { get; set; }
    public ServerMail ServerMail { get; set; } = new();
}

public class ServerMail
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; }
    public bool SSL { get; set; }
    public string Login { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}