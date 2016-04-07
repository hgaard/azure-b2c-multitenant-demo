using System;
using System.IdentityModel.Tokens;
using Auth;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using WebApi.AdalExt;

namespace WebApi
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            var tvps = new TokenValidationParameters
            {
                ValidAudiences = new[] { Config.ExternalUsersClientId, Config.InternalUsersClientId},
            };

            // Add handler for tokens from the Lor AAD
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                // This SecurityTokenProvider fetches the Azure AD B2C metadata & signing keys from the OpenIDConnect metadata endpoint
                AccessTokenFormat = new JwtFormat(tvps, new OpenIdConnectCachingSecurityTokenProvider(string.Format(Config.AadInstance, Config.InternalUsersTenant, string.Empty, Config.DiscoverySuffix, string.Empty))),
                AuthenticationType = Config.InternalUsersTenant
            });

            // Add handler for tokens from the Lor B2C AAD
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                // This SecurityTokenProvider fetches the Azure AD B2C metadata & signing keys from the OpenIDConnect metadata endpoint
                AccessTokenFormat = new JwtFormat(tvps, new OpenIdConnectCachingSecurityTokenProvider(String.Format(Config.AadInstance, Config.ExternalUsersTenant, "v2.0", Config.DiscoverySuffix, "?p=" + Config.CommonPolicy))),
                AuthenticationType = Config.ExternalUsersTenant
            });
        }
    }
}