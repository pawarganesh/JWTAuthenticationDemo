using JWTAuthenticationDemo.Controllers;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace JWTAuthenticationDemo
{
    public class TokenRefresher : ITokenRefresher
    {
        private readonly byte[] key;
        private IJwtAuthenticationManager jwtAuthenticationManager;
        public TokenRefresher(byte[] key,IJwtAuthenticationManager jwtAuthenticationManager)
        {
            this.key = key;
            this.jwtAuthenticationManager = jwtAuthenticationManager;
        }

        public AuthenticationResponse Refresh(RefreshCread refreshCread)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken validateToken;
            var principal = tokenHandler.ValidateToken(refreshCread.JwtToken,
                    new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = false,
                        ValidateAudience = false
                    },out validateToken);

            var jwtToken = validateToken as JwtSecurityToken;

            if(jwtToken == null) //|| !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature, StringComparison.InvariantCultureIgnoreCase)
            {
                throw new SecurityTokenException("Invalid Token Passed");
            }

            var userName = principal.Identity.Name;
            if(refreshCread.RefreshToken != jwtAuthenticationManager.UsersRefreshToken[userName])
            {
                throw new SecurityTokenException("Invalid Token Passed");
            }

            return jwtAuthenticationManager.AuthenticateWithJwtAndRefreshToken(userName,principal.Claims.ToArray());
        }
    }
}
