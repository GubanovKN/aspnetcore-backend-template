using api.Authorization;
using api.Entities;
using api.Models.Users;
using api.Services;
using Microsoft.AspNetCore.Mvc;

namespace api.Controllers;

[Authorize]
[ApiController]
[Route("[controller]")]
public class UsersController(IUserService userService) : ControllerBase
{
    #region Auth
    
    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register(RegisterRequest model)
    {
        if (string.IsNullOrWhiteSpace(model.LastName))
        {
            return BadRequest(new { message = "Не заполнена фамилия" });
        }
        
        if (string.IsNullOrWhiteSpace(model.FirstName))
        {
            return BadRequest(new { message = "Не заполнено имя" });
        }
        
        if (string.IsNullOrWhiteSpace(model.Email))
        {
            return BadRequest(new { message = "Не заполнен Email" });
        }

        userService.Register(model);

        return Ok();
    }

    [AllowAnonymous]
    [HttpPost("authenticate")]
    public IActionResult Authenticate(AuthenticateRequest model)
    {
        var response = userService.Authenticate(model, IpAddress());
        SetTokenCookie(response.RefreshToken);
        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public IActionResult RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = userService.RefreshToken(refreshToken, IpAddress());
        SetTokenCookie(response.RefreshToken);
        return Ok(response);
    }
    
    [AllowAnonymous]
    [HttpPost("forget-password")]
    public IActionResult ForgetPassword(ForgetPasswordRequest model)
    {
        if (string.IsNullOrWhiteSpace(model.Email))
        {
            return BadRequest(new { message = "Не заполнен Email" });
        }

        userService.ForgetPassword(model);

        return Ok();
    }

    [HttpGet("{id}/refresh-tokens")]
    public IActionResult GetRefreshTokens(Guid id)
    {
        var user = userService.GetById(id);
        return Ok(user.RefreshTokens);
    }

    [HttpPost("revoke-token")]
    public IActionResult RevokeToken(RevokeTokenRequest model)
    {
        var token = model.Token ?? Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(token))
            return BadRequest(new { message = "Token is required" });

        userService.RevokeToken(token, IpAddress());
        return Ok(new { message = "Token revoked" });
    }

    #endregion

    #region Users

    [HttpGet("{id}")]
    public IActionResult GetById(Guid id)
    {
        var user = userService.GetById(id);

        return Ok(new GetByIdResponse
        {
            Id = user.Id,
            LastName = user.LastName,
            FirstName = user.FirstName,
            MiddleName = user.MiddleName,
            Email = user.Email,
            Roles = user.UserRoles.Select(p => p.Role).ToList(),
            IsDismissed = user.IsDismissed
        });
    }

    [HttpGet("all")]
    [Authorize(Roles = "Админ")]
    public IActionResult GetAll()
    {
        var users = userService.GetAll();
        return Ok(users);
    }

    [HttpPost("add")]
    [Authorize(Roles = "Админ")]
    public IActionResult Add(AddRequest model)
    {
        if (string.IsNullOrWhiteSpace(model.LastName))
        {
            return BadRequest(new { message = "Не заполнена фамилия" });
        }

        if (string.IsNullOrWhiteSpace(model.FirstName))
        {
            return BadRequest(new { message = "Не заполнено имя" });
        }

        if (string.IsNullOrWhiteSpace(model.MiddleName))
        {
            return BadRequest(new { message = "Не заполнено отчество" });
        }

        if (string.IsNullOrWhiteSpace(model.Email))
        {
            return BadRequest(new { message = "Не заполнен email" });
        }

        if (string.IsNullOrWhiteSpace(model.Password))
        {
            return BadRequest(new { message = "Не заполнен пароль" });
        }

        if (model.Roles == null || model.Roles.Count == 0)
        {
            return BadRequest(new { message = "Не выбраны роли пользователя" });
        }

        userService.Add(model);

        return Ok();
    }

    [HttpPost("edit")]
    [Authorize(Roles = "Админ")]
    public IActionResult Edit(EditRequest model)
    {
        if (string.IsNullOrWhiteSpace(model.LastName))
        {
            return BadRequest(new { message = "Не заполнена фамилия" });
        }

        if (string.IsNullOrWhiteSpace(model.FirstName))
        {
            return BadRequest(new { message = "Не заполнено имя" });
        }

        if (string.IsNullOrWhiteSpace(model.MiddleName))
        {
            return BadRequest(new { message = "Не заполнено отчество" });
        }

        if (string.IsNullOrWhiteSpace(model.Email))
        {
            return BadRequest(new { message = "Не заполнен email" });
        }

        if (model.Roles == null || model.Roles.Count == 0)
        {
            return BadRequest(new { message = "Не выбраны роли пользователя" });
        }

        userService.Edit(model);

        return Ok();
    }

    #endregion

    #region Other methods

    private void SetTokenCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(7)
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }

    private string IpAddress()
    {
        var address = "";

        if (Request.Headers.TryGetValue("X-Forwarded-For", out var forwarded))
        {
            address = forwarded;
        }
        else if (HttpContext.Connection.RemoteIpAddress != null)
        {
            address = HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();   
        }

        return address ?? "0.0.0.0";
    }

    #endregion
}