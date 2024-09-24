using JWTRefreshTokenDemo;
using JWTRefreshTokenDemo.Models;
using JWTRefreshTokenDemo.Repository;
using JWTRefreshTokenDemo.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);

// Add AppDbContext with SQL Server configuration.
// Using the connection string from appsettings.json for the database context.
builder.Services.AddDbContext<AppDbContext>(option =>
{
    option.UseSqlServer(builder.Configuration.GetConnectionString("dbcontext"));
});

// Add Identity with custom password and sign-in options.
// Configuring Identity to use the AppDbContext and adding token providers.
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireUppercase = false; // No need for uppercase in passwords.
    options.Password.RequireDigit = false;     // No digit requirement in passwords.
    options.SignIn.RequireConfirmedEmail = false; // Allow sign-in without confirmed email.
})
.AddEntityFrameworkStores<AppDbContext>()    // Use AppDbContext for Identity.
.AddDefaultTokenProviders();

// Register custom services from the ServicesRegistration class.
builder.Services.AddServiceRegistration(builder.Configuration);

// Register the application's custom services (repositories, JWT, authorization, etc.).
builder.Services.AddScoped<IUserRefreshTokenRepository, UserRefreshTokenRepository>();
builder.Services.AddScoped<IJWTService, JWTService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IUserRefreshTokenService, UserRefreshTokenService>();
builder.Services.AddScoped<IAuthorizationService, AuthorizationService>();


// Configure AutoMapper to map between models and DTOs.
builder.Services.AddAutoMapper(Assembly.GetExecutingAssembly());


builder.Services.AddControllers();

// Swagger setup for API documentation.
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
    //Resolve ASP .NET Core Identity with DI help
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    // Seed the database with roles and initial users.
    await SeedData.Initialize(app.Services, userManager, roleManager);
}

// Configure the HTTP request pipeline. In development mode, use Swagger for API documentation.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger(); // Enable Swagger middleware
    app.UseSwaggerUI(); // Enable Swagger UI for interactive documentation
}
// Register the ExceptionMiddleware to handle exceptions globally
app.UseMiddleware<ExceptionMiddleware>();

app.UseHttpsRedirection(); // Enforce HTTPS for security
app.UseAuthentication(); // Enable JWT Authentication
app.UseAuthorization(); // Enable Authorization middleware


app.MapControllers();

app.Run();
