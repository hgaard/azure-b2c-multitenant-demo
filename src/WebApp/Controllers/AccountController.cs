using System.Web.Mvc;
using WebApp.AdalExt;

namespace WebApp.Controllers
{
    public class AccountController : Controller
    {
        public void Login(AuthType type, bool force = false)
        {
            if (Request.IsAuthenticated && !force) return;

            LoginService.Login(HttpContext, type);
        }

        public void Logout()
        {
            if (!Request.IsAuthenticated) return;

            LoginService.Logout(HttpContext);
        }
    }
}