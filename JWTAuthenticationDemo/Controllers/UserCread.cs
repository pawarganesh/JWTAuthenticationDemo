namespace JWTAuthenticationDemo.Controllers
{
    public class UserCread
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }

    public class RefreshCread
    {
        public string JwtToken { get; set; }
        public string RefreshToken { get; set; }
    }
}