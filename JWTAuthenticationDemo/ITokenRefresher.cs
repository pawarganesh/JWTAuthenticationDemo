using JWTAuthenticationDemo.Controllers;

namespace JWTAuthenticationDemo
{
    public interface ITokenRefresher
    {
        AuthenticationResponse Refresh(RefreshCread refreshCread);
    }
}