using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using System.Web;
using Auth;
using Microsoft.Experimental.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using WebApp.Services;


namespace WebApp.AdalExt
{
    public class LoginService
    {
        public static void Login(HttpContextBase context, AuthType loginType)
        {
            if (loginType == AuthType.External)
            {
                context.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties(
                        new Dictionary<string, string>
                        {
                            {Config.PolicyKey, Config.SignInByEmailPolicyId}
                        })
                    {
                        RedirectUri = "/",
                        AllowRefresh = true,
                        IsPersistent = true
                    }, Config.ExternalUsersTenant);
            }
            else if (loginType == AuthType.Internal)
            {
                context.GetOwinContext()
                    .Authentication.Challenge(new AuthenticationProperties
                    {
                        RedirectUri = "/",
                        AllowRefresh = true,
                        IsPersistent = true
                    }, Config.InternalUsersTenant);
            }
        }

        public static void Logout(HttpContextBase context)
        {
           var authType = context.GetOwinContext().GetAuthType();

            var authority = string.Format(
                CultureInfo.InvariantCulture,
                Config.AadInstance,
                authType == AuthType.Internal ? Config.InternalUsersTenant : Config.ExternalUsersTenant,
                string.Empty, string.Empty);

            var authContext = new AuthenticationContext(authority);

            authContext.TokenCache.Clear();

            if (authType == AuthType.Internal)
            {
                context.GetOwinContext().Authentication.SignOut(
                    Config.InternalUsersTenant,
                    CookieAuthenticationDefaults.AuthenticationType);
            }
            else if (authType == AuthType.External)
            {
                context.GetOwinContext().Authentication.SignOut(
                    new AuthenticationProperties(
                        new Dictionary<string, string>
                    {
                        {Config.PolicyKey, ClaimsPrincipal.Current.FindFirst(Config.AcrClaimType).Value}
                    }), Config.ExternalUsersTenant,
                        CookieAuthenticationDefaults.AuthenticationType);
            }
        }
    }
}
