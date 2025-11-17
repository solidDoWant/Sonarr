using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NLog;
using NzbDrone.Common.EnvironmentInfo;
using NzbDrone.Common.Extensions;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;

namespace Sonarr.Http.Authentication
{
    [AllowAnonymous]
    [ApiController]
    public class AuthenticationController : Controller
    {
        private readonly IAuthenticationService _authService;
        private readonly IConfigFileProvider _configFileProvider;
        private readonly IConfigService _configService;
        private readonly IAppFolderInfo _appFolderInfo;
        private readonly Logger _logger;

        public AuthenticationController(IAuthenticationService authService, IConfigFileProvider configFileProvider, IConfigService configService, IAppFolderInfo appFolderInfo, Logger logger)
        {
            _authService = authService;
            _configFileProvider = configFileProvider;
            _configService = configService;
            _appFolderInfo = appFolderInfo;
            _logger = logger;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromForm] LoginResource resource, [FromQuery] string returnUrl = null)
        {
            var user = _authService.Login(HttpContext.Request, resource.Username, resource.Password);

            if (user == null)
            {
                return Redirect($"~/login?returnUrl={returnUrl}&loginFailed=true");
            }

            var claims = new List<Claim>
            {
                new Claim("user", user.Username),
                new Claim("identifier", user.Identifier.ToString()),
                new Claim("AuthType", AuthenticationType.Forms.ToString())
            };

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = resource.RememberMe == "on"
            };

            try
            {
                await HttpContext.SignInAsync(AuthenticationType.Forms.ToString(), new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies", "user", "identifier")), authProperties);
            }
            catch (CryptographicException e)
            {
                if (e.InnerException is XmlException)
                {
                    _logger.Error(e, "Failed to authenticate user due to corrupt XML. Please remove all XML files from {0} and restart Sonarr", Path.Combine(_appFolderInfo.AppDataFolder, "asp"));
                }
                else
                {
                    _logger.Error(e, "Failed to authenticate user. {0}", e.Message);
                }

                return Unauthorized();
            }

            if (returnUrl.IsNullOrWhiteSpace() || !Url.IsLocalUrl(returnUrl))
            {
                return Redirect(_configFileProvider.UrlBase + "/");
            }

            if (_configFileProvider.UrlBase.IsNullOrWhiteSpace() || returnUrl.StartsWith(_configFileProvider.UrlBase))
            {
                return Redirect(returnUrl);
            }

            return Redirect(_configFileProvider.UrlBase + returnUrl);
        }

        [HttpGet("logout")]
        public async Task<IActionResult> Logout()
        {
            _authService.Logout(HttpContext);
            await HttpContext.SignOutAsync(AuthenticationType.Forms.ToString());
            return Redirect(_configFileProvider.UrlBase + "/");
        }

        [HttpGet("oidc/login")]
        public IActionResult OidcLogin([FromQuery] string returnUrl = null)
        {
            if (!_configService.OidcEnabled)
            {
                return Redirect($"~/login?returnUrl={returnUrl}&loginFailed=true&error=OIDC+not+enabled");
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = returnUrl.IsNullOrWhiteSpace() ? _configFileProvider.UrlBase + "/" : returnUrl
            };

            return Challenge(properties, AuthenticationType.External.ToString());
        }

        [HttpGet("oidc/callback")]
        public async Task<IActionResult> OidcCallback()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(AuthenticationType.External.ToString());

            if (!authenticateResult.Succeeded)
            {
                _logger.Error("OIDC authentication failed: {0}", authenticateResult.Failure?.Message);
                return Redirect($"~/login?loginFailed=true&error={Uri.EscapeDataString(authenticateResult.Failure?.Message ?? "Unknown error")}");
            }

            var usernameClaim = authenticateResult.Principal?.FindFirst(_configService.OidcUsernameClaim)
                             ?? authenticateResult.Principal?.FindFirst(ClaimTypes.Name)
                             ?? authenticateResult.Principal?.FindFirst("name");

            if (usernameClaim == null)
            {
                _logger.Error("OIDC authentication failed: Username claim '{0}' not found", _configService.OidcUsernameClaim);
                return Redirect($"~/login?loginFailed=true&error=Username+claim+not+found");
            }

            var username = usernameClaim.Value;
            _logger.Debug("OIDC user authenticated: {0}", username);

            // Log the OIDC authentication event
            _authService.LogSuccess(HttpContext.Request, username);

            var claims = new List<Claim>
            {
                new Claim("user", username),
                new Claim("AuthType", AuthenticationType.External.ToString())
            };

            // Copy additional claims from OIDC
            foreach (var claim in authenticateResult.Principal.Claims)
            {
                if (claim.Type != _configService.OidcUsernameClaim && claim.Type != ClaimTypes.Name)
                {
                    claims.Add(claim);
                }
            }

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = authenticateResult.Properties?.ExpiresUtc
            };

            // Sign in with cookie authentication
            await HttpContext.SignInAsync(
                AuthenticationType.Forms.ToString(),
                new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies", "user", null)),
                authProperties);

            var returnUrl = authenticateResult.Properties?.RedirectUri;
            if (returnUrl.IsNullOrWhiteSpace() || !Url.IsLocalUrl(returnUrl))
            {
                return Redirect(_configFileProvider.UrlBase + "/");
            }

            if (_configFileProvider.UrlBase.IsNullOrWhiteSpace() || returnUrl.StartsWith(_configFileProvider.UrlBase))
            {
                return Redirect(returnUrl);
            }

            return Redirect(_configFileProvider.UrlBase + returnUrl);
        }

        [HttpGet("oidc/logout")]
        public async Task<IActionResult> OidcLogout()
        {
            if (!_configService.OidcEnabled)
            {
                return await Logout();
            }

            _authService.Logout(HttpContext);

            // Sign out from both cookie and OIDC
            await HttpContext.SignOutAsync(AuthenticationType.Forms.ToString());
            return SignOut(
                new AuthenticationProperties { RedirectUri = _configFileProvider.UrlBase + "/" },
                AuthenticationType.External.ToString());
        }

        [HttpGet("oidc/signedout")]
        public IActionResult OidcSignedOut()
        {
            return Redirect(_configFileProvider.UrlBase + "/");
        }
    }
}
