using System.Linq;
using Auth;
using Microsoft.Owin;

namespace WebApp.B2CUtil
{
    /// <summary>
    /// Extehtion class for determining authentication context
    /// </summary>
    public static class OwinContextExtension
    {
        public static AuthType GetAuthType(this IOwinContext ctxt)
        {
            var audience = ctxt.Authentication.User.Claims.FirstOrDefault(x => x.Type == "aud");
            if (audience == null) return AuthType.None;

            if (audience.Value == Configuration.ExternalUsersClientId)
            {
                return AuthType.External;
            }

            return audience.Value == Configuration.InternalUsersClientId ? AuthType.Internal : AuthType.None;
        }
    }
}