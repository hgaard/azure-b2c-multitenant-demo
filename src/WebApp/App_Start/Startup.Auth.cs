using System;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Threading;
using System.Threading.Tasks;
using Auth;
using Microsoft.Experimental.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using WebApp.AdalExt;
using AuthenticationContext = Microsoft.Experimental.IdentityModel.Clients.ActiveDirectory.AuthenticationContext;


namespace WebApp
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
            });

            AddExternalUsersAuthToOwinRuntime(app);
            AddInternalUsersAuthToOwinRuntime(app);
        }

        private static void AddExternalUsersAuthToOwinRuntime(IAppBuilder app)
        {
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = Auth.Config.ExternalUsersTenant,
                // These are standard OpenID Connect parameters, with values pulled from web.config
                ClientId = Auth.Config.ExternalUsersClientId,
                RedirectUri = Auth.Config.RedirectUri,
                PostLogoutRedirectUri = Auth.Config.RedirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = OnAuthenticationFailed,
                    RedirectToIdentityProvider = OnRedirectToIdentityProvider,
                    AuthorizationCodeReceived = OnAuthorizationCodeReceived
                },
                Scope = "openid offline_access",

                // The PolicyConfigurationManager takes care of getting the correct Azure AD authentication
                // endpoints from the OpenID Connect metadata endpoint.  It is included in the PolicyAuthHelpers folder.
                ConfigurationManager = new PolicyConfigurationManager(
                    string.Format(CultureInfo.InvariantCulture, Auth.Config.AadInstance, Auth.Config.ExternalUsersTenant, "/v2.0",
                        Auth.Config.OidcMetadataSuffix), new[] { Auth.Config.SignUpByEmailPolicyId, Auth.Config.SignInByEmailPolicyId, Auth.Config.ProfilePolicyId }),

                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters
                {
                    NameClaimType = "name",
                }
            });
        }

        private static void AddInternalUsersAuthToOwinRuntime(IAppBuilder app)
        {
            app.UseOpenIdConnectAuthentication(
                 new OpenIdConnectAuthenticationOptions
                 {
                     // The `Authority` represents the v2.0 endpoint - https://login.microsoftonline.com/common/v2.0
                     // The `Scope` describes the permissions that your app will need.  See https://azure.microsoft.com/documentation/articles/active-directory-v2-scopes/
                     // In a real application you could use issuer validation for additional checks, like making sure the user's organization has signed up for your app, for instance.
                     AuthenticationType = Auth.Config.InternalUsersTenant,
                     ClientId = Auth.Config.InternalUsersClientId,
                     Authority = string.Format(CultureInfo.InvariantCulture, Auth.Config.AadInstance, Auth.Config.InternalUsersTenant, null, string.Empty),
                     RedirectUri = Auth.Config.RedirectUri,
                     Notifications = new OpenIdConnectAuthenticationNotifications
                     {
                         AuthenticationFailed = OnAuthenticationFailed,
                         AuthorizationCodeReceived = OnAuthorizationCodeReceived
                     },
                     Scope = "openid email profile",
                     PostLogoutRedirectUri = Auth.Config.RedirectUri,
                     TokenValidationParameters = new TokenValidationParameters
                     {
                         NameClaimType = "name"
                     }
                 });
        }

        private static async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            // The user's objectId is extracted from the claims provided in the id_token, and used to cache tokens in ADAL
            // The authority is constructed by appending your B2C directory's name to "https://login.microsoftonline.com/"
            // The client credential is where you provide your application secret, and is used to authenticate the application to Azure AD
            var userObjectId = notification.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

            var audience = notification.AuthenticationTicket.Identity.FindFirst("aud").Value;
            if (audience == Auth.Config.ExternalUsersClientId)
            {
                var authority = string.Format(CultureInfo.InvariantCulture, Auth.Config.AadInstance, Auth.Config.ExternalUsersTenant, string.Empty, string.Empty);
                var credential = new ClientCredential(Auth.Config.ExternalUsersClientId, Auth.Config.ExternalUsersClientSecret);

                // We don't care which policy is used to access the TaskService, so let's use the most recent policy
                var mostRecentPolicy = notification.AuthenticationTicket.Identity.FindFirst(Auth.Config.AcrClaimType).Value;

                // The Authentication Context is ADAL's primary class, which represents your connection to your B2C directory
                // ADAL uses an in-memory token cache by default.  In this case, we've extended the default cache to use a simple per-user session cache
                var authContext = new AuthenticationContext(authority, new NaiveSessionCache(userObjectId));

                // Here you ask for a token using the web app's clientId as the scope, since the web app and service share the same clientId.
                // The token will be stored in the ADAL token cache, for use in our controllers
                await authContext.AcquireTokenByAuthorizationCodeAsync(notification.Code, new Uri(Auth.Config.RedirectUri), credential,
                    new[] { Auth.Config.ExternalUsersClientId }, mostRecentPolicy);
            }
            else
            {
                var authority = string.Format(CultureInfo.InvariantCulture, Auth.Config.AadInstance, Auth.Config.InternalUsersTenant, string.Empty, string.Empty);
                var credential = new Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential(Auth.Config.InternalUsersClientId, Auth.Config.InternalUsersClientSecret);

                // The Authentication Context is ADAL's primary class, which represents your connection to your B2C directory
                // ADAL uses an in-memory token cache by default.  In this case, we've extended the default cache to use a simple per-user session cache
                var authContext = new Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext(authority);

                // Here you ask for a token using the web app's clientId as the scope, since the web app and service share the same clientId.
                // The token will be stored in the ADAL token cache, for use in our controllers
                await authContext.AcquireTokenByAuthorizationCodeAsync(notification.Code, new Uri(Auth.Config.RedirectUri), credential);
            }
        }

        // This notification can be used to manipulate the OIDC request before it is sent.  Here we use it to send the correct policy.
        private static async Task OnRedirectToIdentityProvider(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var mgr = notification.Options.ConfigurationManager as PolicyConfigurationManager;

            if (mgr == null) return;

            if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
            {
                var config = await mgr.GetConfigurationByPolicyAsync(CancellationToken.None, notification.OwinContext.Authentication.AuthenticationResponseRevoke.Properties.Dictionary[Auth.Config.PolicyKey]);
                notification.ProtocolMessage.IssuerAddress = config.EndSessionEndpoint;
            }
            else
            {
                var config = await mgr.GetConfigurationByPolicyAsync(CancellationToken.None, notification.OwinContext.Authentication.AuthenticationResponseChallenge.Properties.Dictionary[Auth.Config.PolicyKey]);
                notification.ProtocolMessage.IssuerAddress = config.AuthorizationEndpoint;
            }
        }


        // Used for avoiding yellow-screen-of-death
        private static Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            // Todo: handle error and log

            notification.HandleResponse();
            notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            return Task.FromResult(0);
        }
    }
}