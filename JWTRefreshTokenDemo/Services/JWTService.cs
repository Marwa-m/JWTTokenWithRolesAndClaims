using JWTRefreshTokenDemo.Helper;
using JWTRefreshTokenDemo.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTRefreshTokenDemo.Services;

public class JWTService : IJWTService
{
    private readonly IConfiguration _iconfiguration;
    private readonly IUserService _userService;
    private readonly IUserRefreshTokenService _userRefreshTokenService;
    private readonly JwtOptions _jwtSettings;

    public JWTService(IConfiguration iconfiguration,
        IUserService userService,
        IUserRefreshTokenService userRefreshTokenService,
        IOptions<JwtOptions> jwtSettingsOptions)
    {
        _iconfiguration = iconfiguration;
        _userService = userService;
        _userRefreshTokenService = userRefreshTokenService;
        _jwtSettings = jwtSettingsOptions.Value;
    }
    public async Task<Tokens> GenerateTokenAsync(string userId)
    {
        return await GenerateJWTTokens(userId);
    }
    public async Task<Tokens> GenerateRefreshTokenAsync(string userId)
    {
        return await GenerateJWTTokens(userId);
    }

    public (ClaimsPrincipal, JwtSecurityToken) GetPrincipalFromExpiredToken(string token)
    {

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = _jwtSettings.ValidateIssuer,
            ValidIssuers = new[] { _jwtSettings.Issuer },
            ValidateIssuerSigningKey = _jwtSettings.ValidateIssuerSigningKey,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Secret)),
            ValidAudience = _jwtSettings.Audience,
            ValidateAudience = _jwtSettings.ValidateAudience,
            ValidateLifetime = false,
            ClockSkew = TimeSpan.Zero
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        JwtSecurityToken jwtSecurityToken = securityToken as JwtSecurityToken;

        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }
        return (principal, jwtSecurityToken);
    }

    public async Task<string> ValidateRefreshTokenAsync(JwtSecurityToken jwtToken, UserRefreshTokens userRefreshToken)
    {
        if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
        {
            return "Error in Algorithm";
        }
        if (jwtToken.ValidTo > DateTime.UtcNow)
        {
            return "Token is not expired";
        }
        if (userRefreshToken.ExpiryDate < DateTime.UtcNow)
        {
            userRefreshToken.IsRevoked = true;
            userRefreshToken.IsUsed = false;
            await _userRefreshTokenService.UpdateUserRefreshTokens(userRefreshToken);
            return "RefreshToken is expired";
        }
        return ("Success");
    }

    private async Task<Tokens> GenerateJWTTokens(string userId)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                Claims = await _userService.GetClaimsAsync(userId),
                Expires = DateTime.UtcNow.AddDays(_jwtSettings.AccessTokenExpireDate),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Secret)), SecurityAlgorithms.HmacSha256Signature)

            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var refreshToken = GenerateSecureRandomToken();
            return new Tokens { AccessToken = tokenHandler.WriteToken(token), RefreshToken = refreshToken };
        }
        catch (Exception ex)
        {
            return null;
        }
    }


    private string GenerateSecureRandomToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    public async Task<bool> ValidateTokenAsync(string accessToken)
    {
        var handler = new JwtSecurityTokenHandler();

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = _jwtSettings.ValidateIssuer,
            ValidIssuers = new[] { _jwtSettings.Issuer },
            ValidateIssuerSigningKey = _jwtSettings.ValidateIssuerSigningKey,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Secret)),
            ValidAudience = _jwtSettings.Audience,
            ValidateAudience = _jwtSettings.ValidateAudience,
            ValidateLifetime = _jwtSettings.ValidateLifeTime,
        };
        try
        {
            var validator = handler.ValidateToken(accessToken, parameters, out SecurityToken validatedToken);

            if (validator == null)
            {
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            return false;
        }
    }
}
