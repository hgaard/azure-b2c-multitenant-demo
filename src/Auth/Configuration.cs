using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth
{
    public class Configuration
    {
        public const string AcrClaimType = "http://schemas.microsoft.com/claims/authnclassreference";
        public const string PolicyKey = "b2cpolicy";
        public const string OidcMetadataSuffix = "/.well-known/openid-configuration";

        public static string RedirectUri = ConfigurationManager.AppSettings["Auth.RedirectUri"];
        public static string AadInstance = ConfigurationManager.AppSettings["Auth.AadInstance"];

        public static string ExternalUsersTenant = ConfigurationManager.AppSettings["Auth.External.Tenant"];
        public static string ExternalUsersClientId = ConfigurationManager.AppSettings["Auth.External.ClientId"];
        public static string ExternalUsersClientSecret = ConfigurationManager.AppSettings["Auth.External.ClientSecret"];

        public static string InternalUsersTenant = ConfigurationManager.AppSettings["Auth.Internal.Tenant"];
        public static string InternalUsersClientId = ConfigurationManager.AppSettings["Auth.Internal.ClientId"];
        public static string InternalUsersClientSecret = ConfigurationManager.AppSettings["Auth.Internal.ClientSecret"];
        public static string InternalUsersTenantMetadataAddress = ConfigurationManager.AppSettings["Auth.Internal.TenantMetadataAddress"];
        public static string InternalUsersAppIdUri = ConfigurationManager.AppSettings["Auth.Internal.AppIdUri"];

        // B2C policy identifiers
        public static string SignUpByEmailPolicyId = ConfigurationManager.AppSettings["Auth.External.SignUpPolicyId"];
        public static string SignInByEmailPolicyId = ConfigurationManager.AppSettings["Auth.External.SignInPolicyId"];
        public static string ProfilePolicyId = ConfigurationManager.AppSettings["Auth.External.UserProfilePolicyId"];
    }
}
