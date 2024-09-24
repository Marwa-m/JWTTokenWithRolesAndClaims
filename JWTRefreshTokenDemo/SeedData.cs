using JWTRefreshTokenDemo.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace JWTRefreshTokenDemo
{
    public static class SeedData
    {
        public static async Task Initialize(IServiceProvider serviceProvider, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                context.Database.EnsureCreated(); // Ensure the database is created

                var roles = new[] { "Admin", "User" };

                // Check if the roles already exist and create if not
                foreach (var role in roles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        var roleResult = await roleManager.CreateAsync(new IdentityRole(role));
                        if (!roleResult.Succeeded)
                        {
                            throw new Exception($"Failed to create role: {role}");
                        }
                    }
                }
                // Check if the user already exists
                if (!context.Users.Any())
                {
                    var adminEmail = "admin@example.com";
                    var adminPassword = "Password123!";

                    var user = new ApplicationUser
                    {
                        UserName = adminEmail,
                        Email = adminEmail,
                        EmailConfirmed = true
                    };

                    var result = await userManager.CreateAsync(user, adminPassword);

                    if (result.Succeeded)
                    {
                        // Assign the "Admin" role to the user
                        await userManager.AddToRoleAsync(user, "Admin");

                        // Assign claims to the user
                        var claims = new List<Claim>
                    {
                        new Claim("CreateRole", "True"),
                        new Claim("DeleteRole", "True"),
                        new Claim("EditRole", "True")
                    };

                        foreach (var claim in claims)
                        {
                            await userManager.AddClaimAsync(user, claim);
                        }
                    }
                    else
                    {
                        throw new Exception("Failed to create admin user.");
                    }
                }
            }
        }
    }
}
