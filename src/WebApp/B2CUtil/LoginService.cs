using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using System.Web;
using Auth;
using Microsoft.Experimental.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;

namespace WebApp.B2CUtil
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
                            {Configuration.PolicyKey, Configuration.SignInByEmailPolicyId}
                        })
                    {
                        RedirectUri = "/",
                        AllowRefresh = true,
                        IsPersistent = true
                    }, Configuration.ExternalUsersTenant);
            }
            else if (loginType == AuthType.Internal)
            {
                context.GetOwinContext()
                    .Authentication.Challenge(new AuthenticationProperties
                    {
                        RedirectUri = "/",
                        AllowRefresh = true,
                        IsPersistent = true
                    }, Configuration.InternalUsersTenant);
            }
        }

        public static void Logout(HttpContextBase context)
        {
           var authType = context.GetOwinContext().GetAuthType();

            var authority = string.Format(
                CultureInfo.InvariantCulture,
                Configuration.AadInstance,
                authType == AuthType.Internal ? Configuration.InternalUsersTenant : Configuration.ExternalUsersTenant,
                string.Empty, string.Empty);

            var authContext = new AuthenticationContext(authority);

            authContext.TokenCache.Clear();

            if (authType == AuthType.Internal)
            {
                context.GetOwinContext().Authentication.SignOut(
                    Configuration.InternalUsersTenant,
                    CookieAuthenticationDefaults.AuthenticationType);
            }
            else if (authType == AuthType.External)
            {
                context.GetOwinContext().Authentication.SignOut(
                    new AuthenticationProperties(
                        new Dictionary<string, string>
                    {
                        {Configuration.PolicyKey, ClaimsPrincipal.Current.FindFirst(Configuration.AcrClaimType).Value}
                    }), Configuration.ExternalUsersTenant,
                        CookieAuthenticationDefaults.AuthenticationType);
            }
        }
    }
}
