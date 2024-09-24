namespace JWTRefreshTokenDemo.Models;

public record Tokens
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
}