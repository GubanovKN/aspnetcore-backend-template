using System.Net.Mail;
using System.Text.RegularExpressions;

namespace api.Helpers;

public class Normalize
{
    private const string regexPhone = @"^([\+]?[1-9]{1})[1-9][0-9]{9}$";
    
    public static string Email(string email)
    {
        if (!CheckEmail(email))
        {
            throw new AppException("Invalid email");
        }

        return email.ToLower();
    }

    public static bool CheckEmail(string email)
    {
        var trimmedEmail = email.Trim();

        if (trimmedEmail.EndsWith('.'))
        {
            return false;
        }

        try
        {
            var addr = new MailAddress(email);
            return addr.Address == trimmedEmail;
        }
        catch
        {
            return false;
        }
    }

    public static string Phone(string phone)
    {
        if (!CheckPhone(phone))
        {
            throw new AppException("Invalid phone");
        }

        var regex = new Regex(@"[^\d]");
        phone = regex.Replace(phone, "");
        const string format = "#-###-###-####";
        phone = Convert.ToInt64(phone).ToString(format);
        return phone;
    }

    public static bool CheckPhone(string phone)
    {
        return !string.IsNullOrEmpty(phone) && Regex.IsMatch(phone, regexPhone);
    }
}