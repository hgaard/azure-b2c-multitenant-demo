using System.Threading.Tasks;
using System.Web.Mvc;
using Auth;

namespace WebApp.Controllers
{
    [Authorize]
    public class ApiTestController : Controller
    {
        public async Task<ActionResult> Index()
        {
            var client = new ApiClient();

            var token = await client.GetAsync<string>("http://localhost:55473/api/token");


            ViewBag.Token = token;
            ViewBag.TokenDecoded = JWT.JsonWebToken.Decode(token.Split(' ')[1], Config.ExternalUsersClientSecret, false);

            return View();
        }
    }
}