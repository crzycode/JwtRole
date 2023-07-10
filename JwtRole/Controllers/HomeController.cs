using JwtRole.DbModels;
using JwtRole.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtRole.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        public static UserModel usr = new UserModel();
        private readonly IConfiguration _configuration;
        public HomeController(IConfiguration configuration)
        {
            this._configuration = configuration;

        }
        [HttpPost("Register")]
        public async Task<ActionResult<User>>  Register(User user)
        {
            createpassword_hash(user.Password, out byte[] passwordHash, out byte[] passwordSalt);
            usr.Username = user.Username;
            usr.PasswordHash = passwordHash;
            usr.PasswordSalt = passwordSalt;
            return Ok(usr);
        }
        [HttpPost("Login")]
        public async Task<ActionResult> Login(User user)
        {
            if(usr.Username != user.Username)
            {
                return BadRequest("User Not Found");
            }
            if(!verify_hashpassword(user.Password,usr.PasswordHash,usr.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }
            string token = Createtoken(usr);
            var refreshtoken = GenerateRefreshToken();
                SetRefreshToken(refreshtoken);
            return Ok(token);
        }
        [HttpPost("Refreshtoken")]
        public async Task<ActionResult<dynamic>> RefreshToken()
        {
            var refreshtoken = Request.Cookies["RefreshToken"];
            if(!usr.RefreshToken.Equals(refreshtoken))
            {
                return Unauthorized("Invalid Token");
            }
            else if (usr.ExpiredToken < DateTime.Now)
            {
                return Unauthorized("Token Expired");
            }
            else
            {
                string token = Createtoken(usr);
                var newrefreshtoken = GenerateRefreshToken();
                SetRefreshToken(newrefreshtoken);
                return Ok(token);
            }

        }
        private void SetRefreshToken(RefreshToken newrefreshtoken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newrefreshtoken.Expired
            };
            Response.Cookies.Append("RefreshToken",newrefreshtoken.Token, cookieOptions);
            usr.RefreshToken = newrefreshtoken.Token;
            usr.TokenCreated = newrefreshtoken.Created;
            usr.ExpiredToken = newrefreshtoken.Expired;

        }
        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expired = DateTime.Now.AddMinutes(1),
                Created = DateTime.Now
            };
            return refreshToken;
        }
        private string Createtoken(UserModel user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")

            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSetting:Token").Value));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
                
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(1),
                signingCredentials:creds

                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
        private void createpassword_hash(string password,out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA256())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

            }
        }
        private bool verify_hashpassword(string password , byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA256(passwordSalt))
            {
                var compute = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return compute.SequenceEqual(passwordHash);
            }
        }
    }
}
