using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWTAuthenticationDemo.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class NameController : ControllerBase
    {
        private IJwtAuthenticationManager _jwtAuthenticationManager;
        private ITokenRefresher _tokenRefresher;
        public NameController(IJwtAuthenticationManager jwtAuthenticationManager, ITokenRefresher tokenRefresher)
        {
            _jwtAuthenticationManager = jwtAuthenticationManager;
            _tokenRefresher = tokenRefresher;
        }

        // GET: api/<NameController>
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/<NameController>/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate([FromBody] UserCread userCread)
        {
            var token = _jwtAuthenticationManager.Authenticate(userCread.UserName, userCread.Password);
            if(token == null)
                return Unauthorized();
            return Ok(token);
        }

        [AllowAnonymous]
        [HttpPost("AuthenticateWithJwtAndRefreshToken")]
        public IActionResult AuthenticateWithJwtAndRefreshToken([FromBody] UserCread userCread)
        {
            var token = _jwtAuthenticationManager.AuthenticateWithJwtAndRefreshToken(userCread.UserName, userCread.Password);
            if (token == null)
                return Unauthorized();
            return Ok(token);
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshCread refreshCread)
        {
            var token = _tokenRefresher.Refresh(refreshCread);
            if (token == null)
                return Unauthorized();
            return Ok(token);
        }

    }
}
