using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;

namespace WebApp.B2CUtil
{
    /// <summary>
    /// Another class that has been inherited from the b2c examples and will be obsolete when ADAL supports b2c
    /// </summary>
    internal class HttpDocumentRetriever : IDocumentRetriever
    {
        private readonly HttpClient _httpClient;

        public HttpDocumentRetriever()
            : this(new HttpClient())
        {
        }

        public HttpDocumentRetriever(HttpClient httpClient)
        {
            if (httpClient == null)
            {
                throw new ArgumentNullException("httpClient");
            }
            _httpClient = httpClient;
        }

        public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            if (string.IsNullOrWhiteSpace(address))
            {
                throw new ArgumentNullException("address");
            }
            try
            {
                HttpResponseMessage response = await _httpClient.GetAsync(address, cancel).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new IOException("Unable to get document from: " + address, ex);
            }
        }
    }
}
