using api.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace api.Authorization;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AuthorizeAttribute : Attribute, IAuthorizationFilter
{
    public string? Roles { get; set; }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var allowAnonymous = context.ActionDescriptor.EndpointMetadata.OfType<AllowAnonymousAttribute>().Any();
        if (allowAnonymous)
            return;

        var user = (User?)context.HttpContext.Items["User"];

        if (user != null)
        {
            if (string.IsNullOrEmpty(Roles)) return;
            var validate = false;

            var roles = Roles.Split(',');
            foreach (var role in roles)
            {
                if (user.UserRoles != null && user.UserRoles.Any(userRole => role == userRole.Role?.Name))
                {
                    validate = true;
                }

                if (validate)
                {
                    break;
                }
            }

            if (!validate)
            {
                context.Result = new JsonResult(new { message = "Forbidden" })
                    { StatusCode = StatusCodes.Status403Forbidden };
            }
        }
        else
        {
            context.Result = new JsonResult(new { message = "Unauthorized" })
                { StatusCode = StatusCodes.Status401Unauthorized };
        }
    }
}