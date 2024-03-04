using api.Helpers;
using api.Services;
using Microsoft.Extensions.Options;

namespace api.Authorization;

public class JwtMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings)
{
    private readonly AppSettings _appSettings = appSettings.Value;

    public async Task Invoke(HttpContext context, IUserService userService, IJwtUtils jwtUtils)
    {
        var token = context.Request.Headers.Authorization.FirstOrDefault()?.Split(" ").Last();
        var userId = jwtUtils.ValidateJwtUser(token);
        if (userId != null)
        {
            context.Items["User"] = userService.GetById(userId.Value);
        }

        await next(context);
    }
}