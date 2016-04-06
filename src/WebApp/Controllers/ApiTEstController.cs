using System.Threading.Tasks;
using System.Web.Mvc;
using Auth;
using WebApp.Clients;

namespace WebApp.Controllers
{
    [Authorize]
    public class ApiTestController : Controller
    {
        public async Task<ActionResult> Index()
        {
            var client = new TokenApiClient("http://localhost:64017/api/");

            var token = await client.GetToken();


            ViewBag.Token = token;
            ViewBag.TokenDecoded = JWT.JsonWebToken.Decode(token.Split(' ')[1], Configuration.ExternalUsersClientSecret, false);

            return View();
        }
    }
}