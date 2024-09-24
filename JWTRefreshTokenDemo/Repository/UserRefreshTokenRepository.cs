using JWTRefreshTokenDemo.Models;
using Microsoft.EntityFrameworkCore;

namespace JWTRefreshTokenDemo.Repository;

public class UserRefreshTokenRepository : IUserRefreshTokenRepository
{
    private readonly AppDbContext _db;

    public UserRefreshTokenRepository(AppDbContext db)
    {
        _db = db;
    }

    public async Task AddUserRefreshTokenAsync(UserRefreshTokens user)
    {
        await _db.UserRefreshToken.AddAsync(user);
        _db.SaveChanges();
    }
    public async Task UpdateUserRefreshTokenAsync(UserRefreshTokens userRefreshToken)
    {
        await _db.UserRefreshToken.AddAsync(userRefreshToken);
        _db.SaveChanges();
    }

    public async Task DeleteUserRefreshTokensAsync(string userId, string refreshToken)
    {
        var item = await _db.UserRefreshToken.FirstOrDefaultAsync(x => x.UserId == userId && x.RefreshToken == refreshToken);
        if (item != null)
        {
            _db.UserRefreshToken.Remove(item);
        }

    }

    public async Task<UserRefreshTokens> GetSavedRefreshTokenAsync(string userId, Tokens token)
    {
        return await _db.UserRefreshToken.FirstOrDefaultAsync(x => x.UserId == userId &&
                                                x.RefreshToken == token.RefreshToken &&
                                                x.AccessToken == token.AccessToken);
    }


}
