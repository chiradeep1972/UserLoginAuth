using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace UserLoginAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration) 
        {
            _configuration = configuration;
        }
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserRegister request)
        {
            CreatePassword(request.Password, out byte[] passowrd, out byte[] conformpassword);
            user.username = request.UserName;
            user.conformpassword = conformpassword;
            return Ok(user);
        }
        [HttpPost ("login")]
        public async Task<ActionResult<string>> Login(UserRegister request)
        {
            if(user.username != request.UserName)
            {
                return BadRequest("User not found.");
            }
            if(!VarifyPassword(request.Password,user.password,user.conformpassword))
            {
                return BadRequest("Wrong Password.");
            }
            string token = CreateToken(user);
            return Ok(token);
        }
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
              new Claim(ClaimTypes.Name,user.username)  
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                    _configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;

            
        }
        private void CreatePassword(string password,out byte[] conformpassword,out byte[] passwor)
        {
            using (var hmac = new HMACSHA512())
            {
                conformpassword = hmac.Key;
                passwor = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }
        private bool VarifyPassword(string password, byte[] passowrd, byte[] conformpassword)
        {
            using(var hmac = new HMACSHA512(conformpassword))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(conformpassword);
            }
        }
            }
}
