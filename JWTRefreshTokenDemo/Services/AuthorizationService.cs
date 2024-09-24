using JWTRefreshTokenDemo.Helper;
using JWTRefreshTokenDemo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace JWTRefreshTokenDemo.Services
{
    public class AuthorizationService : IAuthorizationService
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public AuthorizationService(RoleManager<IdentityRole> roleManager,
            UserManager<ApplicationUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }
        public async Task<Result> AddRoleAsync(string roleName)
        {
            IdentityRole role = new IdentityRole
            {
                Name = roleName
            };
            var result = await _roleManager.CreateAsync(role);
            if (!result.Succeeded)
            {
                var errorDescription = result.Errors.FirstOrDefault()?.Description;
                return Result.Failure( errorDescription);
            }
            return Result.Success();
        }

        public async Task<Result> DeleteRoleAsync(string roleName)
        {
            // Retrieve the role from the database
            var role = await _roleManager.FindByNameAsync(roleName);

            // Check if the role exists
            if (role == null)
            {
                return Result.Failure($"Role '{roleName}' not found.");
            }

            // Delete the role
            var result = await _roleManager.DeleteAsync(role);
            if (!result.Succeeded)
            {
                return Result.Failure(result.Errors.FirstOrDefault()?.Description ?? "Unknown error occurred.");
            }

            return Result.Success("Deleted Role sucessfully");
        }

        public async Task<List<string>> GetRolesAsync()
        {
            // Retrieve all roles from the database
            var roles = await _roleManager.Roles.ToListAsync();

            // Extract the names of the roles
            var roleNames = roles.Select(r => r.Name).ToList();

            return roleNames;
        }

        #region UserRoles
        public async Task<Result<List<string>>> GetUserRolesAsync(string userName)
        {
            // Retrieve the user from the database
            var user = await _userManager.FindByNameAsync(userName);

            // Check if the user exists
            if (user == null)
            {
                return Result<List<string>>.Failure($"{userName} was not found");
            }
            // Get the roles for the user
            var roles = await _userManager.GetRolesAsync(user);

            return Result<List<string>>.Success(  roles.ToList());
        }
        public async Task<Result> AddRoleToUserAsync(string userName, string roleName)
        {
            // Retrieve the user from the database
            var user = await _userManager.FindByNameAsync(userName);

            // Check if the user exists
            if (user == null)
            {
                return Result.Failure( $"User with Name '{userName}' not found.");
            }
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role == null)
            {
                return Result.Failure($"The role '{roleName}' not found.");
            }
            var result = await _userManager.AddToRoleAsync(user, roleName);

            if (!result.Succeeded)
            {
                return Result.Failure(result.Errors.FirstOrDefault()?.Description ?? "Unknown error occurred.");
            }

            return Result.Success("Success") ;
        }
        public async Task<Result> DeleteRoleFromUserAsync(string userName, string roleName)
        {
            // Retrieve the user from the database
            var user = await _userManager.FindByNameAsync(userName);

            // Check if the user exists
            if (user == null)
            {
                return Result.Failure( $"User '{userName}' not found.");
            }
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role == null)
            {
                return Result.Failure($"The role '{roleName}' not found.");
            }
            var result = await _userManager.RemoveFromRoleAsync(user, roleName);

            if (!result.Succeeded)
            {
                return Result.Failure( result.Errors.FirstOrDefault()?.Description ?? "Unknown error occurred.");
            }

            return Result.Success( "Success");
        }

        #endregion

        #region UserClaims
        public async Task<Result<List<Claim>>> GetUserClaimsAsync(string userName)
        {
            // Retrieve the user from the database
            var user = await _userManager.FindByNameAsync(userName);

            // Check if the user exists
            if (user == null)
            {
                return Result<List<Claim>>.Failure("User is not found");
               // throw new ArgumentNullException("User is not found");
            }

            // Get the roles for the user
            var claims = await _userManager.GetClaimsAsync(user);

            return Result<List<Claim>>.Success( claims.ToList());
        }
        public async Task<Result> AddOrUpdateClaimToUserAsync(string userName, string claimType, string claimValue)
        {
            // Retrieve the user from the database
            var user = await _userManager.FindByNameAsync(userName);

            // Check if the user exists
            if (user == null)
            {
                return Result.Failure( $"User '{userName}' not found.");
            }
            var claimAlreadyExistWithSameValue = _userManager.GetClaimsAsync(user).Result.Any(x=>x.Type==claimType && x.Value==claimValue);
            if (claimAlreadyExistWithSameValue) {
                return Result.Failure("Claim already exists");
            }
            var claim = new Claim(claimType, claimValue);
            var claimAlreadyExistWithDifferentValue = _userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == claimType);
            if(claimAlreadyExistWithDifferentValue!=null)
            {
               var replacedClaim= _userManager.ReplaceClaimAsync(user, claimAlreadyExistWithDifferentValue,claim);
                if (!replacedClaim.IsCompletedSuccessfully)
                {
                    return Result.Failure(replacedClaim.Result.Errors.FirstOrDefault()?.Description ?? "Unknown error occurred.");
                }
                return Result.Success("Claim Updated Succesfully");

            }
            else
            {
                var result = await _userManager.AddClaimAsync(user, claim);

                if (!result.Succeeded)
                {
                    return Result.Failure(result.Errors.FirstOrDefault()?.Description ?? "Unknown error occurred.");
                }
                return Result.Success("Calim Added successfully");

            }


        }
        //delete claim not changed in database
        public async Task<Result> DeleteClaimAsync(string userName, string claimType)
        {
            // Retrieve the user by username
            var user = await _userManager.FindByNameAsync(userName);

            // Check if the user exists
            if (user == null)
            {
                return Result.Failure( $"User '{userName}' not found.");
            }

            // Create the claim to be deleted
            var claim = _userManager.GetClaimsAsync(user).Result.FirstOrDefault(x => x.Type == claimType);
            if (claim == null)
                return Result.Failure($"User {userName} doesn't have the claim {claimType}");
            // Remove the claim
            var result = await _userManager.RemoveClaimAsync(user, claim);

            // Check if the removal succeeded
            if (!result.Succeeded)
            {
                return Result.Failure( result.Errors.FirstOrDefault()?.Description ?? "Unknown error occurred.");
            }
            
            return Result.Success( "Success");
        }

        #endregion
    }
}
