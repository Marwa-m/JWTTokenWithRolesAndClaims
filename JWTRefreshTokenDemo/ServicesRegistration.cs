using JWTRefreshTokenDemo.Helper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

namespace JWTRefreshTokenDemo;

public static class ServicesRegistration
{
    public static IServiceCollection AddServiceRegistration(this IServiceCollection services, IConfiguration configuration)
    {
       services.ConfigureOptions<JwtOptionsSetup>();
        // Bind the JwtSettings section in appsettings.json to a strongly-typed object.
        var jwtSettings = configuration.GetSection("Jwt").Get<JwtOptions>();
        // Set up authentication with JWT Bearer scheme.
        services.AddAuthentication(x =>
        {
            x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
       .AddJwtBearer(x =>
       {
           // JWT bearer token configuration.
           x.RequireHttpsMetadata = false; // For development purposes, can be set to true in production.
           x.SaveToken = true;             // Save the token once validated.
           x.TokenValidationParameters = new TokenValidationParameters
           {
               ValidateIssuer = jwtSettings.ValidateIssuer,
               ValidIssuers = new[] { jwtSettings.Issuer },
               ValidateIssuerSigningKey = jwtSettings.ValidateIssuerSigningKey,
               IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings.Secret)),
               ValidAudience = jwtSettings.Audience,
               ValidateAudience = jwtSettings.ValidateAudience,
               ValidateLifetime = jwtSettings.ValidateLifeTime,
           };
       });

        // Swagger configuration for API documentation.
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo { Title = "JWT Authentication API With Roles And Claims", Version = "v1" });
            c.EnableAnnotations();

            c.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
            {
                Description = "JWT Authorization header using the Bearer scheme (Example: 'Bearer 12345abcdef')",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.ApiKey,
                Scheme = JwtBearerDefaults.AuthenticationScheme
            });

            // Security requirement for Swagger.
            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
            {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = JwtBearerDefaults.AuthenticationScheme
                }
            },
            Array.Empty<string>()
            }
           });
        });


        // Configure authorization policies.
        services.AddAuthorization(option =>
        {
            // Policy requires the "CreateRole" claim
            option.AddPolicy("CreateRole", policy =>
            {
                policy.RequireClaim("CreateRole", "True");
            });
            // Policy requires the "DeleteRole" claim
            option.AddPolicy("DeleteRole", policy =>
            {
                policy.RequireClaim("DeleteRole", "True");
            });
            // Policy requires the "EditRole" claim
            option.AddPolicy("EditRole", policy =>
            {
                policy.RequireClaim("EditRole", "True");
            });
        });

        return services;
    }
}