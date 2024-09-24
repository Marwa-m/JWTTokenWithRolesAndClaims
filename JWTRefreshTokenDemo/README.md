### Overview
This project demonstrates the implementation of JWT (JSON Web Token) authentication and authorization with ASP.NET Core. The main purpose is to provide a robust token-based authentication system with roles and claims management. The project includes several API endpoints for managing user authentication and role-based access control.

## Key Features:
1. JWT Token Generation:
  Generates JWT tokens with user-specific claims and roles.
2. Sign-in and Registration:
 Provides APIs for user sign-in and registration.

3. Role and Claim Management:
 APIs to manage user roles and claims for more granular control over permissions.
4. Token Refresh:
 Implements a refresh token mechanism to securely issue new access tokens without requiring the user to log in again.
5. Token Validation:
 An endpoint for validating JWT tokens to check their validity.
6. Error Handling:
 Centralized error handling using a middleware pattern to ensure a clean and maintainable codebase.

## API Endpoints:
* POST /signin: Authenticate users and issue JWT tokens.
* POST /register: Register new users and generate a JWT token upon successful registration.
* POST /refresh-token: Refresh expired JWT tokens with a valid refresh token.
* GET /validate-token: Validate if a token is still valid.
* GET /get-all-users: Retrieves all users (requires authorization).

* GET /get-all-roles: Retrieves all roles (requires authorization).
* GET /get-user-roles: Retrieves all roles for a specific user.
* POST /add-role: Adds role for role-based authentication (requires claim "CreateRole").
* POST /User/add-role: Add role to a specific user.
* POST /delete-role: Delete role from user  (requires claim "DeleteRole").
* POST User/delete-role: Delete role from a specific user.
* GET /User/Claims: Retrieves all claims for specific user.
* POST /User/add-or-update-claim: Adds or updates claims for specific user for more detailed permission control.
* POST /User/delete-claim: Delete claim from a specific user.


### JWT Settings
The `appsettings.json` file contains important JWT configuration settings, such as the secret key, issuer, audience, token expiration times, and validation flags.

Here's a breakdown of the key settings:

- `secret`: The key used to sign JWTs.
- `issuer`: The authentication server that issues the token.
- `audience`: The intended recipient of the token (e.g., your API).
- `validateAudience`, `validateIssuer`, etc.: Flags to enforce token validation.
- `AccessTokenExpireDate` and `RefreshTokenExpireDate`: Control the expiration periods of access and refresh tokens.

For a more detailed explanation, see [JWT Authentication Overview](https://jwt.io/introduction).

### Program.cs Overview
The Program.cs file is the entry point for configuring and running the API. Below is a breakdown of its responsibilities:

## 1. Database Configuration
The API uses Entity Framework Core with SQL Server. The connection string is specified in the appsettings.json file under the "ConnectionStrings" section.
```
builder.Services.AddDbContext<AppDbContext>(option =>
{
    option.UseSqlServer(builder.Configuration.GetConnectionString("dbcontext"));
});
```

## 2. Identity and Authentication Setup
ASP.NET Identity is used for managing users and roles. It has relaxed password policies to allow easier password creation (e.g., no uppercase or digit required). JWT-based authentication is configured using settings from the appsettings.json file.

```
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();
```

## 3. Custom Services and Repositories
Custom services like JWTService, UserService, and repositories like UserRefreshTokenRepository are registered with the dependency injection (DI) container.

```
builder.Services.AddScoped<IUserRefreshTokenRepository, UserRefreshTokenRepository>();
builder.Services.AddScoped<IJWTService, JWTService>();
```

## 4. Middleware Setup
The API uses various middleware components for handling authentication, authorization, HTTPS redirection, and API documentation generation with Swagger.

```
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
```

## 5. Seeding Data
On application startup, the database is seeded with initial data such as roles and users.

```
await SeedData.Initialize(app.Services, userManager, roleManager);
```

### ServicesRegistration.cs Overview
The ServicesRegistration.cs file is a custom extension class that simplifies the registration of services for JWT, Swagger, and Authorization policies.

## JWT Authentication:
This section binds JWT settings from appsettings.json and configures the JwtBearer authentication scheme. Tokens are validated against the issuer, audience, and signing key.

```
services.AddAuthentication().AddJwtBearer(...);
```

## Swagger Configuration:
Swagger is configured to generate API documentation and include JWT authorization in the Swagger UI. This allows you to interact with the API endpoints directly from the documentation interface.

```
services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Generate JWT Token", Version = "v1" });
    c.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, ...);
});
```

## Authorization Policies:
Custom authorization policies are created, which require specific claims for role management operations like creating, deleting, or editing roles.

```
services.AddAuthorization(options =>
{
    options.AddPolicy("CreateRole", policy => policy.RequireClaim("CreateRole", "True"));
});
```

### Database Migration
This project uses Entity Framework Core for database migrations. Below is a brief explanation of how migrations are handled and the commands required to manage them.

## 1. Creating a Migration
To create a new migration after modifying your models or database context, use the following command:
```
dotnet ef migrations add InitialCreate
```

## 2. Applying Migrations
To apply the migrations and update your database, run the following command:
```
dotnet ef database update
```

### Seed Data Initialization
The project includes a SeedData class that initializes default roles and an admin user when the application starts. This ensures that the roles and an initial admin account are available without manual setup.

* Roles: On first run, the SeedData class creates roles like Admin and User if they don't already exist.
* Admin User: An admin user with the email admin@example.com is created with a default password (Password123!) and assigned the Admin role.
* Claims: The admin user is also assigned specific claims, such as CreateRole, DeleteRole, and EditRole, which are used for authorization policies in the application.

 The seed data ensures that the application has the minimum required setup to run properly, especially for role-based authorization.

### JWTService Class
The *JWTService* is a core part of this application responsible for managing JWT-based authentication and authorization. Below is an overview of the key functionality:
* Generate JWT Tokens:
The `GenerateJWTTokens` method creates a JWT access token and a secure refresh token for a given user. It uses user-specific claims (such as roles and permissions) and applies the signing credentials defined in the app's configuration.
* Token Validation:
 The `ValidateTokenAsync` method ensures that the access token is still valid by checking its signature, audience, issuer, and expiration.
* Handling Expired Tokens:
 The `GetPrincipalFromExpiredToken` method is used to extract claims from an expired token to allow token refreshing without requiring the user to log in again.
* Refresh Token Validation:
The `ValidateRefreshTokenAsync` method checks the validity of a refresh token, including whether it has expired or been used previously.
*Secure Token Generation:
 For refresh tokens, the `GenerateSecureRandomToken` method generates cryptographically secure random tokens.

 This class works closely with the `JwtSettings` from the `appsettings.json` file to manage the security, expiration, and validation logic for tokens.

## Usage:
* Token Generation:
 The `GenerateTokenAsync` method is used to generate both access and refresh tokens.
* Token Validation:
 The `ValidateTokenAsync` method verifies if a token is valid and has not been tampered with.
* Token Refresh:
 The `GenerateRefreshTokenAsync` method allows users to refresh their session without logging in again, provided their refresh token is still valid.

 By handling both access and refresh tokens, JWTService plays a vital role in securing the API endpoints and managing user sessions.

 ### AuthorizationService Class
 The `AuthorizationService` is a service that manages user roles and claims within the application. It provides a set of methods to manage role-based and claim-based authorization.
 ## Key Features:
1. Role Management:
* AddRoleAsync: Creates a new role in the application.
* DeleteRoleAsync: Removes an existing role.
* GetRolesAsync: Retrieves all available roles.
2. User Role Management:
* GetUserRolesAsync: Retrieves all roles assigned to a user by their user ID.
* AddRoleToUserAsync: Assigns a role to a specific user.
* DeleteRoleFromUserAsync: Removes a role from a specific user.
3. User Claims Management:
* GetUserClaimsAsync: Retrieves all claims associated with a user.
* AddClaimToUserAsync: Adds a new claim to a user.
* DeleteClaimAsync: Removes a claim from a user.

## Usage:
1. Role Management:

* Adding a Role: Use the AddRoleAsync method to create a new role in the system, ensuring proper permission management.
* Deleting a Role: The DeleteRoleAsync method is used to remove an existing role from the system.
2. User Role Management:
* Assigning Roles to Users: The AddRoleToUserAsync method helps assign roles to users to manage what actions they can perform within the application.
* Retrieving User Roles: The GetUserRolesAsync method can be used to check which roles are assigned to a particular user.
3. User Claims:

* Adding Claims: The AddOrUpdateClaimToUserAsync method allows you to add specific claims to a user Or Updated it if already exists, such as custom permissions like "CanCreateReport" or "IsAdmin".
* Deleting Claims: The DeleteClaimAsync method removes specific claims from a user if their permissions have changed.