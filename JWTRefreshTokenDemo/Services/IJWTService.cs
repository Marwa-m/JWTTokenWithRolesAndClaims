using JWTRefreshTokenDemo.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JWTRefreshTokenDemo.Services;

public interface IJWTService
{
    Task<Tokens> GenerateTokenAsync(string userId);
    Task<Tokens> GenerateRefreshTokenAsync(string userId);
    (ClaimsPrincipal, JwtSecurityToken) GetPrincipalFromExpiredToken(string token);
    Task<string> ValidateRefreshTokenAsync(JwtSecurityToken jwtToken, UserRefreshTokens userRefreshToken);
    Task<bool> ValidateTokenAsync(string token);
}
