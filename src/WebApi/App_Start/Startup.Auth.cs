using System;
using System.Configuration;
using System.IdentityModel.Tokens;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using WebApi.AdalExt;

namespace WebApi
{
    public partial class Startup
    {
        // These values are pulled from web.config
        public static string AadInstance = ConfigurationManager.AppSettings["Auth.AadInstance"];
        public static string TenantInternal = ConfigurationManager.AppSettings["Auth.Internal.Tenant"];
        public static string ClientIdInternal = ConfigurationManager.AppSettings["Auth.Internal.ClientId"];
        public static string TenantExternal = ConfigurationManager.AppSettings["Auth.External.Tenant"];
        public static string ClientIdExternal = ConfigurationManager.AppSettings["Auth.External.ClientId"];
        public static string CommonPolicy = ConfigurationManager.AppSettings["Auth.External.PolicyId"];
        private const string DiscoverySuffix = ".well-known/openid-configuration";

        public void ConfigureAuth(IAppBuilder app)
        {
            // Add handler for tokens from the Lor AAD
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                // This SecurityTokenProvider fetches the Azure AD B2C metadata & signing keys from the OpenIDConnect metadata endpoint
                AccessTokenFormat = new JwtFormat(new TokenValidationParameters()
                {
                    ValidAudience = ClientIdInternal
                }, 
                new OpenIdConnectCachingSecurityTokenProvider(string.Format(AadInstance, TenantInternal, string.Empty, DiscoverySuffix, string.Empty))),
                AuthenticationType = TenantInternal
            });

            // Add handler for tokens from the Lor B2C AAD
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                // This SecurityTokenProvider fetches the Azure AD B2C metadata & signing keys from the OpenIDConnect metadata endpoint
                AccessTokenFormat = new JwtFormat(
                    new TokenValidationParameters
                    {
                        ValidAudience = ClientIdExternal
                    }, 
                    new OpenIdConnectCachingSecurityTokenProvider(string.Format(AadInstance, TenantExternal, "v2.0", DiscoverySuffix, "?p=" + CommonPolicy))),
                AuthenticationType = TenantExternal
            });
        }
    }
}