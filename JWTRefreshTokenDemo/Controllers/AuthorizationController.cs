using JWTRefreshTokenDemo.Helper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IAuthorizationService = JWTRefreshTokenDemo.Services.IAuthorizationService;

namespace JWTRefreshTokenDemo.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthorizationController : ControllerBase
    {
        private readonly IAuthorizationService _authorizationService;

        public AuthorizationController(IAuthorizationService authorizationService)
        {
            _authorizationService = authorizationService;
        }
        [HttpGet]
        [Route("get-all-roles")]
        public async Task<IActionResult> Get()
        {
            var result = await _authorizationService.GetRolesAsync();
            return Ok(result);
            
        }
        [HttpPost]
        [Route("add-role")]
        [Authorize(policy: "CreateRole")]
        public async Task<IActionResult> AddRoleAsync(string roleName)
        {

            var result = await _authorizationService.AddRoleAsync(roleName);
            if (!result.IsSuccess)
            {
                return BadRequest(result);
            }
            return Ok(result);
        }
        [HttpPost]
        [Route("delete-role")]
        [Authorize(policy: "DeleteRole")]
        public async Task<IActionResult> DeleteRoleAsync(string roleName)
        {

            var result = await _authorizationService.DeleteRoleAsync(roleName);
            if (!result.IsSuccess)
            {
                return BadRequest(result.Message);
            }
            return Ok(result.Message);
        }

        #region UserRoles
        [HttpPost]
        [Route("get-user-roles")]
        public async Task<IActionResult> GetUserRoles(string userName)
        {
            var result = await _authorizationService.GetUserRolesAsync(userName);
            if (!result.IsSuccess) 
                return BadRequest(result.Message);
            return Ok(result);
        }

        [HttpPost]
        [Route("User/add-role")]
        public async Task<IActionResult> AddRoleToUser(string userName, string roleName)
        {
            var result = await _authorizationService.AddRoleToUserAsync(userName, roleName);
            return Ok(result);
        }
        [HttpPost]
        [Route("User/delete-role")]
        public async Task<IActionResult> DeleteRoleFromUserAsync(string userName, string roleName)
        {

            var result = await _authorizationService.DeleteRoleFromUserAsync(userName, roleName);
            if (!result.IsSuccess)
            {
                return BadRequest(result.Message);
            }
            return Ok(result.Message);
        }
        #endregion

        #region UserClaims
        [HttpGet]
        [Route("User/Claims")]
        public async Task<IActionResult> GetUserClaims(string userName)
        {
            var result = await _authorizationService.GetUserClaimsAsync(userName);
            if (!result.IsSuccess)
                return BadRequest(result.Message);
            return Ok(result);
        }

        [HttpPost]
        [Route("User/add-or-update-claim")]
        public async Task<IActionResult> AddOrUpdateClaimToUser(string userName, string claimType, string claimValue)
        {
            var result = await _authorizationService.AddOrUpdateClaimToUserAsync(userName, claimType, claimValue);
           if(result.IsSuccess)
            return Ok(result.Message);
           return BadRequest(result.Message);
        }
        [HttpPost]
        [Route("User/delete-claim")]
        public async Task<IActionResult> DeleteClaimFromUserAsync(string userName, string claimType)
        {

            var result = await _authorizationService.DeleteClaimAsync(userName, claimType);
            if (!result.IsSuccess )
            {
                return BadRequest(result.Message);
            }
            return Ok(result.Message);
        }
        #endregion
    }
}
