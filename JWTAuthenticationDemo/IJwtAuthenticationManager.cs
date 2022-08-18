using System.Security.Claims;

namespace JWTAuthenticationDemo
{
    public interface IJwtAuthenticationManager
    {
        string Authenticate(string username, string password);

        AuthenticationResponse AuthenticateWithJwtAndRefreshToken(string username, string password);

        AuthenticationResponse AuthenticateWithJwtAndRefreshToken(string username, Claim[] claims);

        IDictionary<string, string> UsersRefreshToken { get; set; }
    }
}
