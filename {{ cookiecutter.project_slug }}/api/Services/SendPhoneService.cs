using System.Net.Mail;
using api.Helpers;
using Microsoft.Extensions.Options;

namespace api.Services;

public interface ISendPhoneService
{
    void Send(string phone, string text);
}

public class SendPhoneService(IOptions<AppSettings> appSettings) : ISendPhoneService
{
    private readonly AppSettings _appSettings = appSettings.Value;

    public void Send(string phone, string text)
    {
        if (Constants.IsDevelopmentEnviroment())
        {
            Console.WriteLine($"Send phone: {phone} - {text}");
            return;
        }
    }
}