using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;


namespace BlazrLinkedinLogin.Auth
{
    public class AuthStateProvider : AuthenticationStateProvider
    {
        private readonly ILocalStorageService _localStorage;

        private readonly HttpClient _client;

        public AuthStateProvider(ILocalStorageService localStorage, HttpClient client)
        {
            _localStorage = localStorage;
            _client = client;
        }        

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            string? token = await _localStorage.GetItemAsStringAsync("localToken");

            var identity = new ClaimsIdentity();

            _client.DefaultRequestHeaders.Authorization = null;

            if(!string.IsNullOrWhiteSpace(token))
            {
                var handler = new JwtSecurityTokenHandler();
                var handledToken = handler.ReadJwtToken(token);
                var payload = handledToken.Payload;
                var claims = payload.Claims;
                identity = new ClaimsIdentity(claims, "jwt");
                _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }

            var user = new ClaimsPrincipal(identity);
            var state = new AuthenticationState(user);

            NotifyAuthenticationStateChanged(Task.FromResult(state));
            return state;
        }
    }
}