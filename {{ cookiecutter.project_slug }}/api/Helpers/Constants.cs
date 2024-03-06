namespace api.Helpers;

public class Constants
{
    private static string[] DevelopmentEnviroments = { "Owner", "Development" };

    public static bool IsDevelopmentEnviroment() =>
        DevelopmentEnviroments.Contains(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"));
}