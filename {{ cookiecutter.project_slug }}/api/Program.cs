using System.Text.Json.Serialization;
using api.Authorization;
using api.Helpers;
using api.Services;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
{
    var services = builder.Services;
    var config = builder.Configuration;
    var logging = builder.Logging;

    logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Warning);

    var databaseConnection = config.GetConnectionString("DefaultConnection");
    services.AddDbContext<DataContext>(options => options.UseNpgsql(databaseConnection));

    var redisConnection = config.GetConnectionString("RedisConnection");
    services.AddStackExchangeRedisCache(options => { options.Configuration = redisConnection; });

    services.AddControllers().AddJsonOptions(x =>
        x.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull);
    services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

    services.Configure<FormOptions>(x =>
    {
        x.BufferBody = true;
        x.ValueCountLimit = int.MaxValue;
    });

    services.AddSwaggerGen();

    services.AddScoped<IJwtUtils, JwtUtils>();
    services.AddScoped<ISendMailService, SendMailService>();
    services.AddScoped<ISendPhoneService, SendPhoneService>();
    services.AddScoped<IAuthService, AuthService>();
    services.AddScoped<IUserService, UserService>();
}

var app = builder.Build();
AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

app.UseRouting();

app.UseMiddleware<ErrorHandlerMiddleware>();
app.UseMiddleware<JwtMiddleware>();

if (app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Owner"))
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.Run();