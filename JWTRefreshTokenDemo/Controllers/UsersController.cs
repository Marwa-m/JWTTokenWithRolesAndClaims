using AutoMapper;
using JWTRefreshTokenDemo.Helper;
using JWTRefreshTokenDemo.Models;
using JWTRefreshTokenDemo.Repository;
using JWTRefreshTokenDemo.Services;
using JWTRefreshTokenDemo.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JWTRefreshTokenDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    public class UsersController : ControllerBase
    {
        private readonly IJWTService _jWTService;
        private readonly IUserRefreshTokenRepository _userRefreshTokenRepository;
        private readonly JwtOptions _jwtSettings;
        private readonly IUserService _userService;
        private readonly IMapper _mapper;
        private readonly ILogger<UsersController> _logger;

        public UsersController(IJWTService jwtService,
            IUserRefreshTokenRepository userRefreshTokenRepository,
             IOptions<JwtOptions> jwtSettingsOptions,
            IUserService userService,
            IMapper mapper,
            ILogger<UsersController> logger)
        {
            _jWTService = jwtService ?? throw new ArgumentNullException(nameof(jwtService));
            _userRefreshTokenRepository = userRefreshTokenRepository ?? throw new ArgumentNullException(nameof(userRefreshTokenRepository));
            _jwtSettings = jwtSettingsOptions.Value;
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _logger = logger?? throw new ArgumentNullException(nameof(logger));
        }


        [Authorize]
        [HttpGet]
        [Route("get-all-users")]
        public async Task<IActionResult> Get()
        {
                var users = await _userService.GetUsersAsync().ConfigureAwait(false);
                return Ok(Result<List<GetUserViewModel>>.Success(users));
        }
        [HttpPost]
        [Route("signin")]
        public async Task<IActionResult> SignInAsync(UserLoginViewModel model)
        {
                var validUser = await _userService.IsValidUserAsync(model.Email, model.Password).ConfigureAwait(false);

                if (!validUser)
                {
                    return Unauthorized(Result.Failure( "Invalid username or password..."));
                }
                var user = await _userService.GetUserByEmail(model.Email).ConfigureAwait(false);
                var token = await _jWTService.GenerateTokenAsync(user.Id).ConfigureAwait(false);

                if (token == null)
                {
                    return Unauthorized(Result.Failure( "Invalid Attempt.."));
                }
                var refreshToken = new UserRefreshTokens
                {
                    AddedTime = DateTime.UtcNow,
                    ExpiryDate = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpireDate),
                    IsRevoked = false,
                    IsUsed = true,
                    RefreshToken = token.RefreshToken,
                    AccessToken = token.AccessToken,
                    UserId = user.Id
                };

                await _userRefreshTokenRepository.AddUserRefreshTokenAsync(refreshToken).ConfigureAwait(false);
                return Ok(Result<Tokens>.Success(token));
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> RegisterAsync(RegisterUserViewModel model)
        {
            //mapping
            ApplicationUser user = _mapper.Map<ApplicationUser>(model);

            var result = await _userService.AddUserAsync(user, model.Password);
            if (!result.IsSuccess)
            {
                return  BadRequest(result);
            }

            var token = await _jWTService.GenerateTokenAsync(user.Id);

            if (token == null)
            {
                return Unauthorized("Invalid Attempt..");
            }
            UserRefreshTokens obj = new UserRefreshTokens
            {
                AddedTime = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpireDate),
                IsRevoked = false,
                IsUsed = true,
                RefreshToken = token.RefreshToken,
                AccessToken = token.AccessToken,
                UserId = user.Id
            };

            await _userRefreshTokenRepository.AddUserRefreshTokenAsync(obj);
            return Ok(token);
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> Refresh(Tokens token)
        {
           
                (ClaimsPrincipal principal, JwtSecurityToken jwtSecurityToken) = _jWTService.GetPrincipalFromExpiredToken(token.AccessToken);
                var userIdClaim = principal.Claims.FirstOrDefault(x => x.Type == "Id");
            if (userIdClaim == null)
            {
                return BadRequest("Invalid token.");
            }
           

                    var user = await _userService.GetUserById(userIdClaim.Value);
                    if (user is null)
                        return Unauthorized("User not found!");

                    var savedRefreshToken = await _userRefreshTokenRepository.GetSavedRefreshTokenAsync(user.Id, token);

                    if (savedRefreshToken == null || savedRefreshToken.RefreshToken != token.RefreshToken)
                    {
                        return Unauthorized("Invalid refresh token!");
                    }
                    var validationMessage = await _jWTService.ValidateRefreshTokenAsync(jwtSecurityToken, savedRefreshToken);
                    if (validationMessage != "Success")
                    {
                        return BadRequest(validationMessage);
                    }
                    var newJwtToken = await _jWTService.GenerateRefreshTokenAsync(user.Id);

                    if (newJwtToken == null)
                    {
                        return Unauthorized("Failed to generate new JWT token.");
                    }


                    UserRefreshTokens obj = new UserRefreshTokens
                    {
                        AddedTime = DateTime.UtcNow,
                        ExpiryDate = DateTime.UtcNow.AddMinutes(_jwtSettings.RefreshTokenExpireDate),
                        IsRevoked = false,
                        IsUsed = true,
                        RefreshToken = token.RefreshToken,
                        AccessToken = token.AccessToken,
                        UserId = user.Id
                    };
                    await _userRefreshTokenRepository.DeleteUserRefreshTokensAsync(user.Id, token.RefreshToken);
                    await _userRefreshTokenRepository.AddUserRefreshTokenAsync(obj);

                    return Ok(newJwtToken);
        }

        [HttpGet]
        [Route("Validate-Token")]
        public async Task<IActionResult> ValidateTokenAsync(string token)
        {
            var isValid = await _jWTService.ValidateTokenAsync(token);

            return Ok(isValid);
        }

    }
}
