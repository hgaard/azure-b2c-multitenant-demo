using System.Globalization;
using Auth;
using Microsoft.Experimental.IdentityModel.Clients.ActiveDirectory;


namespace WebApp.B2CUtil
{
    public static class AuthenticationHelper
    {
        public static ClientCredential GetClientCredential(string audience)
        {
            return audience == Configuration.ExternalUsersClientId
                ? new ClientCredential(Configuration.ExternalUsersClientId, Configuration.ExternalUsersClientSecret)
                : new ClientCredential(Configuration.InternalUsersClientId, Configuration.InternalUsersClientSecret);
        }

        public static string GetAuthority(string audience)
        {
            var tenant = audience == Configuration.ExternalUsersClientId
                ? Configuration.ExternalUsersTenant
                : Configuration.InternalUsersTenant;

            return string.Format(CultureInfo.InvariantCulture, Configuration.AadInstance, tenant, string.Empty, string.Empty);
        }

        public static string CachedToken { get; set; }
    }
}
