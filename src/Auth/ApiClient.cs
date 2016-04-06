using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Web;
using System.Web.Routing;
using Adalv4 = Microsoft.Experimental.IdentityModel.Clients.ActiveDirectory;
using Adalv2 = Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;

namespace Auth
{
    public abstract class ApiClient
    {
        private readonly string _authApiUrl;
        private readonly HttpClient _client;
        private readonly string _endpoint;
        private IDictionary<string, object> _queryParameters = new Dictionary<string, object>();

        protected ApiClient(string url, string noun, string authApiUrl)
        {
            _authApiUrl = authApiUrl;
            _client = new HttpClient();
            _client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            _endpoint = string.Format("{0}{1}", url, noun);
        }

        protected T Get<T>(string path = "")
        {
            return GetAsync<T>(path).Result;
        }

        protected async Task<T> GetAsync<T>(string path = "")
        {
            var contentString = await GetStringAsync(path).ConfigureAwait(false);

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

        protected async Task<Uri> Post<TRequest>(TRequest item, string path = "")
        {
            var endpoint = string.Format("{0}{1}", _endpoint, path);
            var response = await _client.PostAsJsonAsync(endpoint, item);
            return response.IsSuccessStatusCode ? response.Headers.Location : null;
        }

        private async Task<string> GetStringAsync(string path = "")
        {
            var token = await AcquireAuthenticationToken();
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var queryString = string.Empty;
            if (_queryParameters.Any())
                queryString = "?" + BuildQueryString();

            var request = string.Format("{0}{1}/{2}", _endpoint, path, queryString);
            if (string.IsNullOrWhiteSpace(path))
                request = string.Format("{0}/{1}", _endpoint, queryString);

            var response = await _client.SendAsync(new HttpRequestMessage(HttpMethod.Get, request)).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var newToken = await RefreshToken();
                _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", newToken);

                response = await _client.SendAsync(new HttpRequestMessage(HttpMethod.Get, request)).ConfigureAwait(false);
            }

            var result = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (response.IsSuccessStatusCode == false)
            {
                Trace.TraceError("Error getting response. {0}", result);
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                throw new ApplicationException(string.Format("Internal Server Error: {0}", result));
            }
            response.EnsureSuccessStatusCode();

            return result;
        }

        private static async Task<string> AcquireAuthenticationToken()
        {
            var audience = ClaimsPrincipal.Current.FindFirst("aud").Value;
            if (audience == Configuration.ExternalUsersClientId)
            {
                return await AcquireB2CToken(audience);
            }

            var result = await AcquireAadToken(audience);
            return result.AccessToken;

        }

        private static async Task<Adalv2.AuthenticationResult> AcquireAadToken(string audience)
        {
            var authority = GetAuthority(audience);
            var credential = new Adalv2.ClientCredential(Configuration.InternalUsersClientId, Configuration.InternalUsersClientSecret);
            var authContext = new Adalv2.AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(Configuration.InternalUsersClientId, credential);
            return result;
        }

        private static async Task<string> AcquireB2CToken(string audience)
        {
            var userObjectId = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            var authority = GetAuthority(audience);
            var credential = new Adalv4.ClientCredential(Configuration.ExternalUsersClientId, Configuration.ExternalUsersClientSecret);
            var authContext = new Adalv4.AuthenticationContext(authority, new NaiveSessionCache(userObjectId));
            var mostRecentPolicy = ClaimsPrincipal.Current.FindFirst(Configuration.AcrClaimType).Value;
            var result = await authContext.AcquireTokenSilentAsync(new string[] { Configuration.ExternalUsersClientId }, credential, Adalv4.UserIdentifier.AnyUser, mostRecentPolicy);
            return result.Token;
        }

        public async Task<string> RefreshToken()
        {
            var audience = ClaimsPrincipal.Current.FindFirst("aud").Value;

            var authority = GetAuthority(audience);
            var credential = new Adalv2.ClientCredential(Configuration.InternalUsersClientId, Configuration.InternalUsersClientSecret);
            var authContext = new Adalv2.AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(Configuration.InternalUsersClientId, credential);

            var res = await authContext.AcquireTokenByRefreshTokenAsync(result.RefreshToken, credential, Configuration.InternalUsersClientId);
            return res.AccessToken;
        }

        private string BuildQueryString()
        {
            var queryBuilder = new StringBuilder();
            foreach (var parameter in _queryParameters)
            {
                queryBuilder.Append(string.Format("{0}={1}&", parameter.Key, parameter.Value));
            }
            return HttpUtility.ParseQueryString(queryBuilder.ToString().TrimEnd('&')).ToString();
        }

        protected void SetQueryParameters(object parameters)
        {
            _queryParameters = new RouteValueDictionary(parameters);
        }

        public static string GetAuthority(string audience)
        {
            var tenant = audience == Configuration.ExternalUsersClientId
                ? Configuration.ExternalUsersTenant
                : Configuration.InternalUsersTenant;

            return string.Format(CultureInfo.InvariantCulture, Configuration.AadInstance, tenant, string.Empty, string.Empty);
        }
    }
}


