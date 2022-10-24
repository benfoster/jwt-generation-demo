using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Minid;

namespace JwtApi;


public class ResourceTokenGenerator
{
    private readonly JwtOptions _options;
    private readonly ILogger<ResourceTokenGenerator> _logger;

    public ResourceTokenGenerator(IOptions<JwtOptions> options, ILogger<ResourceTokenGenerator> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public string GenerateToken(Id resourceId)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_options.SigningKey);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            Claims = new Dictionary<string, object> {
                {  JwtRegisteredClaimNames.Jti, resourceId.ToString() },
                {  JwtRegisteredClaimNames.Sub, Id.NewId("acc") } // Platform account ID
            },
            Expires = DateTime.UtcNow.AddDays(7), // How long we want the application to be valid for
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature
            )
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public bool TryValidate(string? resourceToken, out Id resourceId)
    {
        resourceId = Id.Empty;

        if (string.IsNullOrWhiteSpace(resourceToken))
        {
            return false;
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_options.SigningKey);
        try
        {
            tokenHandler.ValidateToken(resourceToken, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = _options.Audience,
                ValidIssuer = _options.Issuer,
                // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;

            if (Id.TryParse(jwtToken.Id /* jti */, out resourceId))
            {
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to validate resource token");
        }

        return false;
    }
}

public class JwtOptions
{
    public string Issuer { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public string SigningKey { get; set; } = null!;
}