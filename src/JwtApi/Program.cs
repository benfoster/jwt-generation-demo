using JwtApi;
using Minid;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddTransient<ResourceTokenGenerator>();

builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));

var app = builder.Build();


app.MapPost("/initiate", (ResourceTokenGenerator genenerator) =>
{

    var id = Id.NewId("app");

    string resourceToken = genenerator.GenerateToken(id);

    return new
    {
        id,
        token = resourceToken
    };
});

app.MapPost("/validate", (ResourceTokenGenerator generator, ValidationRequest validationRequest) =>
{

    bool isValid = generator.TryValidate(validationRequest.Token, out Id resourceId);

    return new
    {
        valid = isValid,
        id = resourceId
    };
});

app.Run();

public class ValidationRequest
{
    public string? Token { get; set; }
}
