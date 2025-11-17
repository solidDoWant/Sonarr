using System;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Diacritical;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;

namespace Sonarr.Http.Authentication
{
    public static class AuthenticationBuilderExtensions
    {
        private static readonly Regex CookieNameRegex = new Regex(@"[^a-z0-9]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static AuthenticationBuilder AddApiKey(this AuthenticationBuilder authenticationBuilder, string name, Action<ApiKeyAuthenticationOptions> options)
        {
            return authenticationBuilder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(name, options);
        }

        public static AuthenticationBuilder AddNone(this AuthenticationBuilder authenticationBuilder, string name)
        {
            return authenticationBuilder.AddScheme<AuthenticationSchemeOptions, NoAuthenticationHandler>(name, options => { });
        }

        public static AuthenticationBuilder AddExternal(this AuthenticationBuilder authenticationBuilder, string name, IConfigService configService)
        {
            if (configService.OidcEnabled)
            {
                return authenticationBuilder.AddOpenIdConnect(name, options =>
                {
                    options.Authority = configService.OidcAuthority;
                    options.ClientId = configService.OidcClientId;
                    options.ClientSecret = configService.OidcClientSecret;
                    options.ResponseType = OpenIdConnectResponseType.Code;
                    options.SaveTokens = true;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.CallbackPath = configService.OidcCallbackPath;
                    options.SignedOutCallbackPath = configService.OidcSignedOutCallbackPath;

                    // Configure scopes
                    options.Scope.Clear();
                    var scopes = configService.OidcScopes.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var scope in scopes)
                    {
                        options.Scope.Add(scope.Trim());
                    }

                    // Map the username claim
                    options.TokenValidationParameters.NameClaimType = configService.OidcUsernameClaim;

                    // Handle authentication events
                    options.Events = new OpenIdConnectEvents
                    {
                        OnTokenValidated = context =>
                        {
                            // Extract username from the configured claim
                            var usernameClaim = context.Principal?.FindFirst(configService.OidcUsernameClaim)
                                             ?? context.Principal?.FindFirst(ClaimTypes.Name)
                                             ?? context.Principal?.FindFirst("name");

                            if (usernameClaim == null)
                            {
                                context.Fail("Username claim not found in token");
                                return Task.CompletedTask;
                            }

                            // Create a new claims identity with the OIDC claims
                            var claims = context.Principal.Claims.ToList();
                            var identity = new ClaimsIdentity(claims, name);
                            context.Principal = new ClaimsPrincipal(identity);

                            return Task.CompletedTask;
                        },
                        OnAuthenticationFailed = context =>
                        {
                            context.HandleResponse();
                            context.Response.Redirect($"/login?loginFailed=true&error={Uri.EscapeDataString(context.Exception.Message)}");
                            return Task.CompletedTask;
                        }
                    };
                });
            }
            else
            {
                return authenticationBuilder.AddScheme<AuthenticationSchemeOptions, NoAuthenticationHandler>(name, options => { });
            }
        }

        public static AuthenticationBuilder AddAppAuthentication(this IServiceCollection services)
        {
            services.AddOptions<CookieAuthenticationOptions>(nameof(AuthenticationType.Forms))
                .Configure<IConfigFileProvider>((options, configFileProvider) =>
                {
                    // Replace diacritics and replace non-word characters to ensure cookie name doesn't contain any valid URL characters not allowed in cookie names
                    var instanceName = configFileProvider.InstanceName;
                    instanceName = instanceName.RemoveDiacritics();
                    instanceName = CookieNameRegex.Replace(instanceName, string.Empty);

                    options.Cookie.Name = $"{instanceName}Auth";
                    options.AccessDeniedPath = "/login?loginFailed=true";
                    options.LoginPath = "/login";
                    options.ExpireTimeSpan = TimeSpan.FromDays(7);
                    options.SlidingExpiration = true;
                    options.ReturnUrlParameter = "returnUrl";
                });

            var serviceProvider = services.BuildServiceProvider();
            var configService = serviceProvider.GetRequiredService<IConfigService>();

            return services.AddAuthentication()
                .AddNone(nameof(AuthenticationType.None))
                .AddExternal(nameof(AuthenticationType.External), configService)
                .AddCookie(nameof(AuthenticationType.Forms))
                .AddApiKey("API", options =>
                {
                    options.HeaderName = "X-Api-Key";
                    options.QueryName = "apikey";
                })
                .AddApiKey("SignalR", options =>
                {
                    options.HeaderName = "X-Api-Key";
                    options.QueryName = "access_token";
                });
        }
    }
}
