using System.Net;
using System.Text.Json;

namespace api.Helpers;

public class ErrorHandlerMiddleware(RequestDelegate next)
{
    public async Task Invoke(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception error)
        {
            if (error is not AppException)
            {
                Console.WriteLine(error.ToString());
            }

            var response = context.Response;
            response.ContentType = "application/json";

            response.StatusCode = error switch
            {
                AppException e => (int)HttpStatusCode.BadRequest,
                KeyNotFoundException e => (int)HttpStatusCode.NotFound,
                _ => (int)HttpStatusCode.InternalServerError
            };

            var result = JsonSerializer.Serialize(new { message = error?.Message });
            await response.WriteAsync(result);
        }
    }
}