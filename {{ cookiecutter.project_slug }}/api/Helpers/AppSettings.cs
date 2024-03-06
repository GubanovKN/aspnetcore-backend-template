namespace api.Helpers;

public class AppSettings
{
    public string Secret { get; set; } = string.Empty;
    public int RefreshTokenTTL { get; set; }
    public ServerMailSettings ServerMail { get; set; } = new();
    public OAuthSettings OAuth { get; set; } = new();
}

public class ServerMailSettings
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; }
    public bool SSL { get; set; }
    public string Login { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}

public class OAuthSettings
{
    public GoogleSettings Google { get; set; } = new();
}

public class GoogleSettings
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string RedirectURL { get; set; } = string.Empty;
}