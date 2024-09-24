using JWTRefreshTokenDemo.Helper;
using JWTRefreshTokenDemo.Models;
using JWTRefreshTokenDemo.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace JWTRefreshTokenDemo.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<UserService> _logger;
        private readonly AppDbContext _dbContext;

        public UserService(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<UserService> logger,
            AppDbContext dbContext)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _roleManager = roleManager;
            _signInManager = signInManager;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dbContext = dbContext;
            _logger.LogInformation("UserService created");
            _logger = logger;
        }



        public async Task<Dictionary<string, object>> GetClaimsAsync(string id)
        {
            var user = await GetUserById(id);
            if (user == null)
            {
                return new Dictionary<string, object>();
            }
            var claims = new Dictionary<string, object>
        {
            { ClaimTypes.Email, user.Email },
            { ClaimTypes.NameIdentifier, user.UserName },
            { nameof(ApplicationUser.Id), user.Id.ToString() }
        };

            var roles = await _userManager.GetRolesAsync(user);
            if (roles != null && roles.Count() > 0)
            {
                claims.Add(ClaimTypes.Role, roles.ToList());

            }



            var userClaims = await _userManager.GetClaimsAsync(user);

            foreach (var claim in userClaims)
            {
                claims.Add(claim.Type, claim.Value);
            }

            return claims;
        }


        public async Task<Result> AddUserAsync(ApplicationUser user, string password)
        {
            var trans = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                //if email is exist return an error message
                var isExistuser = await _userManager.FindByEmailAsync(user.Email);
                if (isExistuser != null)
                    return Result.Failure( "EmailIsExist");
                isExistuser = await _userManager.FindByNameAsync(user.UserName);
                if (isExistuser != null)
                    return Result.Failure( "UserNameIsExist");
                var createResult = await _userManager.CreateAsync(user, password);
                if (!createResult.Succeeded)
                {
                    return Result.Failure( createResult.Errors.FirstOrDefault().Description);
                }
                // Create the "USER" role if it doesn't exist
                if (!await _roleManager.RoleExistsAsync("USER"))
                {
                    var role = new IdentityRole("USER");
                    await _roleManager.CreateAsync(role);
                }
                await _userManager.AddToRoleAsync(user, "User");

                await trans.CommitAsync();
                return Result.Success( "Success");
            }
            catch (Exception ex)
            {
                await trans.RollbackAsync();
                return Result.Failure( "Failed");
            }
        }


        public async Task<bool> IsValidUserAsync(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return false;
            }
            var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
            if (!result.Succeeded)
            {
                return false;

            }
            return true;
        }

        public async Task<ApplicationUser> GetUserByEmail(string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }

        public async Task<List<GetUserViewModel>> GetUsersAsync()
        {
            var users = await _userManager.Users
                                          .Select(user => new GetUserViewModel
                                          {
                                              UserName = user.UserName,
                                              Email = user.Email
                                          })
                                          .ToListAsync();

            return users;
        }

        public async Task<ApplicationUser> GetUserById(string id)
        {
            return await _userManager.FindByIdAsync(id.ToString());
        }
    }
}