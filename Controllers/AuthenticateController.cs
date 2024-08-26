using _20242608_JWTAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace _20242608_JWTAuth.Controllers
{
  
        [Route("api/[controller]")]
        [ApiController]
        public class AuthenticateController : ControllerBase
        {
            private readonly UserManager<IdentityUser> _userManager;
            private readonly RoleManager<IdentityRole> _roleManager;
            private readonly IConfiguration _configuration;
            public AuthenticateController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
            {
                _userManager = userManager;
                _roleManager = roleManager; _configuration = configuration;
            }

            [HttpPost]
            [Route("login")]
            public async Task<IActionResult> Login([FromBody] LoginModel model)
            {
                var user = await _userManager.FindByNameAsync(model.Username);
                if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    var userRoles = await _userManager.GetRolesAsync(user);
                    var authClaims = new List<Claim> {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                    foreach (var userRole in userRoles) { authClaims.Add(new Claim(ClaimTypes.Role, userRole)); }
                    var token = GetToken(authClaims);
                    return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token), expiration = token.ValidTo });
                }
                return Unauthorized();
            }

            [HttpPost]
            [Route("register")]
            public async Task<IActionResult> Register([FromBody] RegisterModel model)
            {
                var userExists = await _userManager.FindByNameAsync(model.Username);
                if (userExists != null) return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
                IdentityUser user = new() { Email = model.Email, SecurityStamp = Guid.NewGuid().ToString(), UserName = model.Username };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded) return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
                return Ok(new Response { Status = "Success", Message = "User created successfully!" });
            }

            [HttpPost]
            [Route("register-admin")]
            public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
            {
                var userExists = await _userManager.FindByNameAsync(model.Username);
                if (userExists != null)
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
                IdentityUser user = new() { Email = model.Email, SecurityStamp = Guid.NewGuid().ToString(), UserName = model.Username };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
                if (!await _roleManager.RoleExistsAsync(UserRoles.Admin)) await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
                if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
                if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
                {
                    await _userManager.AddToRoleAsync(user, UserRoles.Admin);
                }
                if (await _roleManager.RoleExistsAsync(UserRoles.Admin)) { await _userManager.AddToRoleAsync(user, UserRoles.User); }
                return Ok(new Response { Status = "Success", Message = "User created successfully!" });
            }
            private JwtSecurityToken GetToken(List<Claim> authClaims)
            {
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
                var token = new JwtSecurityToken(issuer: _configuration["JWT:ValidIssuer"], audience: _configuration["JWT:ValidAudience"], expires: DateTime.Now.AddHours(3), claims: authClaims, signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)); 
            return token; }
}




    //    In program.cs mod


// For Entity Frameworkbuilder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(configuration.GetConnectionString("ConnStr")));// For Identitybuilder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();// Adding Authenticationbuilder.Services.AddAuthentication(options =>{    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;})// Adding Jwt Bearer.AddJwtBearer(options =>{    options.SaveToken = true;    options.RequireHttpsMetadata = false;    options.TokenValidationParameters = new TokenValidationParameters(){        ValidateIssuer = true,        ValidateAudience = true,        ValidAudience = configuration["JWT:ValidAudience"],        ValidIssuer = configuration["JWT:ValidIssuer"],        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]))};});


        //////


        // Authentication & Authorizationapp.UseAuthentication();app.UseAuthorization();

    

    
}
