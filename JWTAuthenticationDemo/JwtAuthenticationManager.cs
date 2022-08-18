using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthenticationDemo
{
    public class JwtAuthenticationManager : IJwtAuthenticationManager
    {
        private readonly string key;
        private readonly IRefreshTokenGenerator refreshTokenGenerator;

        private readonly IDictionary<string, string> users = new Dictionary<string, string>
        { {"test1","password1"}, {"test2","password2"} };

        public IDictionary<string, string> UsersRefreshToken { get; set; }

        public JwtAuthenticationManager(string key, IRefreshTokenGenerator refreshTokenGenerator)
        {
            this.key = key;
            this.refreshTokenGenerator = refreshTokenGenerator;
            UsersRefreshToken = new Dictionary<string, string>();
        }

       

        public string Authenticate(string username, string password)
        {
            if(!users.Any(u => u.Key == username && u.Value == password))
            {
                return null;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(key);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, username)
                }),
                Expires = DateTime.UtcNow.AddSeconds(15),
                SigningCredentials = new SigningCredentials(
                                    new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public AuthenticationResponse AuthenticateWithJwtAndRefreshToken(string username, Claim[] claims)
        {
            var tokenKey = Encoding.ASCII.GetBytes(key);
            var jwtSecurityToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddSeconds(15),
                    signingCredentials: new SigningCredentials(
                                    new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
                );

            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            var refreashToken = refreshTokenGenerator.GenerateToken();

            if(UsersRefreshToken.ContainsKey(username))
            {
                UsersRefreshToken[username] = refreashToken;
            }
            else
            {
                UsersRefreshToken.Add(username, refreashToken);
            }            

            return new AuthenticationResponse
            {
                JwtToken = token,
                RefreashToken = refreashToken
            };
        }

        public AuthenticationResponse AuthenticateWithJwtAndRefreshToken(string username, string password)
        {
            if (!users.Any(u => u.Key == username && u.Value == password))
            {
                return null;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(key);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, username)
                }),
                Expires = DateTime.UtcNow.AddSeconds(15),
                SigningCredentials = new SigningCredentials(
                                    new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            var refreashToken = refreshTokenGenerator.GenerateToken();
            if (UsersRefreshToken.ContainsKey(username))
            {
                UsersRefreshToken[username] = refreashToken;
            }
            else
            {
                UsersRefreshToken.Add(username, refreashToken);
            }

            return new AuthenticationResponse 
            { 
                JwtToken = tokenHandler.WriteToken(token),
                RefreashToken = refreashToken
            };
        }
    }
}
