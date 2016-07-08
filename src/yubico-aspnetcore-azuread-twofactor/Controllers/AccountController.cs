using System;
using System.Diagnostics;
using System.Linq;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using yubicoaspnetcoreazureadtwofactor.Helpers;

namespace yubicoaspnetcoreazureadtwofactor.Controllers
{
    public class AccountController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private ISession _session => _httpContextAccessor.HttpContext.Session;
        private IConfiguration _configuration;

        public AccountController(IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
            _configuration = configuration;
        }

        [HttpPost]
        public IActionResult TwoFactorSignIn([FromBody] YubiKeyUser yubiKeyUser)
        {
            if (HttpContext.User.Identity.IsAuthenticated && _session.GetString("YubicoClientStatus") != null && _session.GetString("YubicoClientStatus").Equals("Ok"))
            {
                return new JsonResult(new { status = true });
            }
            if (HttpContext.User.Identity.IsAuthenticated && (_session.GetString("YubicoClientStatus") == null || !_session.GetString("YubicoClientStatus").Equals("Ok")))
            {
                var clientId = _configuration.GetValue<string>("YubiKey:clientId");
                var apiKey = _configuration.GetValue<string>("YubiKey:apiKey");
                var sync = "";
                var nonce = "";
                var otp = yubiKeyUser.OTP;
                var yubikeyotp = new U2FLib.YubicoDotNetClient.YubicoClient(clientId);
                var client = new U2FLib.YubicoDotNetClient.YubicoClient(clientId);
                if (!string.IsNullOrEmpty(apiKey))
                {
                    client.SetApiKey(apiKey);
                }
                if (!string.IsNullOrEmpty(sync))
                {
                    client.SetSync(sync);
                }
                if (!string.IsNullOrEmpty(nonce))
                {
                    client.SetNonce(nonce);
                }
                try
                {
                    var sw = Stopwatch.StartNew();
                    var response = client.Verify(otp);
                    sw.Stop();
                    if (response != null)
                    {
                        Debug.WriteLine("response in: {0}{1}", sw.ElapsedMilliseconds, Environment.NewLine);
                        Debug.WriteLine("Status: {0}{1}", response.Status, Environment.NewLine);
                        Debug.WriteLine("Public ID: {0}{1}", response.PublicId, Environment.NewLine);
                        Debug.WriteLine("Use/Session Counter: {0} {1}{2}", response.UseCounter, response.SessionCounter, Environment.NewLine);
                        Debug.WriteLine(string.Format("Url: {0}", response.Url));
                        var testing123 = _configuration.GetValue<string>("Authentication:AzureAd:Tenant");
                        var yubiKeyIdentity = _configuration.GetValue<string>("YubiKey:YubiKeyIdentity");
                        _session.SetString("YubicoClientStatus", response.Status.ToString());
                        SetClientAttempts();
                        if (response.Status.Equals(U2FLib.YubicoDotNetClient.YubicoResponseStatus.Ok) && response.PublicId.Equals(yubiKeyIdentity))
                        {
                            return new JsonResult(new { status = true });
                        }
                    }
                    else
                    {
                        return new JsonResult(new { status = false, statusMessage = string.Format("Failure in validation: {0}{1}", "Null result returned, error in call", Environment.NewLine) });
                    }
                }
                catch (U2FLib.YubicoDotNetClient.YubicoValidationFailure yvf)
                {
                    Debug.WriteLine("Failure in validation: {0}{1}", yvf.Message, Environment.NewLine);
                    _session.SetString("YubicoClientStatus", yvf.Message);
                    SetClientAttempts();
                    return new JsonResult(new { status = false, statusMessage = string.Format("Failure in validation: {0}{1}", yvf.Message, Environment.NewLine) });
                }
                // Redirect to home page if the user is authenticated.
                return new JsonResult(new {status=true});
            }

            return View();
        }

        private string SetClientAttempts()
        {
            var yubicoClientAttempts = _session.GetString("YubicoClientAttempts");
            _session.SetString("YubicoClientAttempts",
                (string.IsNullOrEmpty(yubicoClientAttempts) ? 1 : Convert.ToInt32(yubicoClientAttempts) + 1).ToString());
            return _session.GetString("YubicoClientAttempts");
        }

        public IActionResult TwoFactorSignIn()
        {

            if (HttpContext.User.Identity.IsAuthenticated && _session.GetString("YubicoClientStatus") != null && _session.GetString("YubicoClientStatus").Equals("Ok"))
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
            if (HttpContext.User.Identity.IsAuthenticated && (_session.GetString("YubicoClientStatus") == null || !_session.GetString("YubicoClientStatus").Equals("Ok")))
            {
                return View();
            }
            return RedirectToAction(nameof(HomeController.Error), "Home", new { message = string.Format("Failure in validation: {0}{1}", "User is not Authenticated.", Environment.NewLine) });

        }

        public IActionResult SignIn()
        {
            var redirectUri = Url.Action("TwoFactorSignIn", "Account", values: null, protocol: Request.Scheme);
            var challengeResult = Challenge(new AuthenticationProperties {  RedirectUri = redirectUri }, OpenIdConnectDefaults.AuthenticationScheme);
            
            return challengeResult;
        }

        public IActionResult SignOut()
        {
            _session.Remove("YubicoClientStatus");
            var callbackUrl = Url.Action("SignedOut", "Account", values: null, protocol: Request.Scheme);
            return SignOut(new AuthenticationProperties { RedirectUri = callbackUrl }, CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);
        }

        public IActionResult SignedOut()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                // Redirect to home page if the user is authenticated.
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return View();
        }

        public IActionResult AccessDenied(string message)
        {
            if (HttpContext.User.Identity.IsAuthenticated && !HttpContext.Session.Keys.Contains("YubicoClientStatus"))
            {
                return RedirectToAction(nameof(AccountController.TwoFactorSignIn), "Account");
            }
            ViewBag.Message = message + " Yubico client status: " + HttpContext.Session.GetString("YubicoClientStatus");
            ViewBag.DisplayRetryLink = false;
            ViewBag.YubicoClientAttempts = Convert.ToInt32(Convert.ToInt32(_session.GetString("YubicoClientAttempts")));
            if (ViewBag.YubicoClientAttempts < 3)
            {
                ViewBag.RetryLink = new PathString("/Account/TwoFactorSignIn");
                ViewBag.DisplayRetryLink = true;
            }
            return View();
        }

        public IActionResult Error(string message)
        {
            ViewBag.Message = message;
            return View();
        }
    }
}
