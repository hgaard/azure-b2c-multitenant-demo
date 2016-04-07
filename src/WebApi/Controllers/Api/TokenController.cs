using System.Web.Http;

namespace WebApi.Controllers.Api
{
    [Authorize]
    public class TokenController : ApiController
    {
        public string Get()
        {
            var token = Request.Headers.Authorization.ToString();

            return token;
        }
    }
}