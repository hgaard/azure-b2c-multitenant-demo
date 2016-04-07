using System;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using Adalv4 = Microsoft.Experimental.IdentityModel.Clients.ActiveDirectory;
using Adalv2 = Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;

namespace Auth
{
    public class ApiClient
    {
        private readonly HttpClient _client;

        public ApiClient()
        {
            _client = new HttpClient();
            _client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        protected T Get<T>(string url)
        {
            return GetAsync<T>(url).Result;
        }

        public async Task<T> GetAsync<T>(string url)
        {
            var contentString = await GetStringAsync(url).ConfigureAwait(false);

            try
            {
                return JsonConvert.DeserializeObject<T>(contentString);
            }
            catch (Exception ex)
            {
                Trace.TraceError("Error parsing response. {0} {1} {2}", ex.Message, ex.StackTrace, contentString);
                throw;
            }
        }

        private async Task<string> GetStringAsync(string url)
        {
            var token = await AcquireAuthenticationToken();
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _client.SendAsync(new HttpRequestMessage(HttpMethod.Get, url)).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var newToken = await RefreshToken();
                _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", newToken);

                response = await _client.SendAsync(new HttpRequestMessage(HttpMethod.Get, url)).ConfigureAwait(false);
            }

            var result = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (response.IsSuccessStatusCode == false)
            {
                Trace.TraceError("Error getting response. {0}", result);
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                throw new ApplicationException($"Internal Server Error: {result}");
            }
            response.EnsureSuccessStatusCode();

            return result;
        }

        private static async Task<string> AcquireAuthenticationToken()
        {
            var audience = ClaimsPrincipal.Current.FindFirst("aud").Value;
            if (audience == Config.ExternalUsersClientId)
            {
                return await AcquireB2CToken(audience);
            }

            var result = await AcquireAadToken(audience);
            return result.AccessToken;

        }

        private static async Task<Adalv2.AuthenticationResult> AcquireAadToken(string audience)
        {
            var authority = GetAuthority(audience);
            var credential = new Adalv2.ClientCredential(Config.InternalUsersClientId, Config.InternalUsersClientSecret);
            var authContext = new Adalv2.AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(Config.InternalUsersClientId, credential);
            return result;
        }

        private static async Task<string> AcquireB2CToken(string audience)
        {
            var userObjectId = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            var authority = GetAuthority(audience);
            var credential = new Adalv4.ClientCredential(Config.ExternalUsersClientId, Config.ExternalUsersClientSecret);
            var authContext = new Adalv4.AuthenticationContext(authority, new NaiveSessionCache(userObjectId));
            var mostRecentPolicy = ClaimsPrincipal.Current.FindFirst(Config.AcrClaimType).Value;
            var result = await authContext.AcquireTokenSilentAsync(new string[] { Config.ExternalUsersClientId }, credential, Adalv4.UserIdentifier.AnyUser, mostRecentPolicy);
            return result.Token;
        }

        public async Task<string> RefreshToken()
        {
            var audience = ClaimsPrincipal.Current.FindFirst("aud").Value;

            var authority = GetAuthority(audience);
            var credential = new Adalv2.ClientCredential(Config.InternalUsersClientId, Config.InternalUsersClientSecret);
            var authContext = new Adalv2.AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(Config.InternalUsersClientId, credential);

            var res = await authContext.AcquireTokenByRefreshTokenAsync(result.RefreshToken, credential, Config.InternalUsersClientId);
            return res.AccessToken;
        }

        public static string GetAuthority(string audience)
        {
            var tenant = audience == Config.ExternalUsersClientId
                ? Config.ExternalUsersTenant
                : Config.InternalUsersTenant;

            return string.Format(CultureInfo.InvariantCulture, Config.AadInstance, tenant, string.Empty, string.Empty);
        }
    }
}


