using System.Net.Mail;
using api.Helpers;
using Microsoft.Extensions.Options;

namespace api.Services;

public interface ISendMailService
{
    void Send(string email, string subject, string body);
}

public class SendMailService(IOptions<AppSettings> appSettings) : ISendMailService
{
    private readonly AppSettings _appSettings = appSettings.Value;

    public void Send(string email, string subject, string body)
    {
        try
        {
            if (Constants.IsDevelopmentEnviroment())
            {
                Console.WriteLine($"Send email: {email} - {subject} - {body}");
                return;
            }
            
            var mySmtpClient = new SmtpClient(_appSettings.ServerMail.Host, _appSettings.ServerMail.Port);
            mySmtpClient.EnableSsl = _appSettings.ServerMail.SSL;

            mySmtpClient.UseDefaultCredentials = false;
            var basicAuthenticationInfo = new
                System.Net.NetworkCredential(_appSettings.ServerMail.Login, _appSettings.ServerMail.Password);
            mySmtpClient.Credentials = basicAuthenticationInfo;

            var from = new MailAddress(_appSettings.ServerMail.Email, _appSettings.ServerMail.Name);
            var to = new MailAddress(email);
            var myMail = new MailMessage(from, to);

            myMail.Subject = subject;
            myMail.SubjectEncoding = System.Text.Encoding.UTF8;

            myMail.Body = body;
            myMail.BodyEncoding = System.Text.Encoding.UTF8;
            myMail.IsBodyHtml = true;

            mySmtpClient.Send(myMail);
        }
        catch (SmtpException)
        {
            throw new AppException("Sorry, something went wrong. Please try again later.");
        }
    }
}