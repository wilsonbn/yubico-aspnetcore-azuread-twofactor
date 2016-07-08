using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace yubicoaspnetcoreazureadtwofactor.Helpers
{
    internal class YubiKeyHandler : AuthorizationHandler<YubiKeyRequirement>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        public ISession Session => _httpContextAccessor.HttpContext.Session;

        internal YubiKeyHandler(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, YubiKeyRequirement requirement)
        {
            var _httpContext = _httpContextAccessor.HttpContext;
            if (((System.Security.Claims.ClaimsIdentity)context.User.Identity).IsAuthenticated.Equals(true) && requirement.YubiKeyUser(Session))
            {
                context.Succeed(requirement);
            }
            if (_httpContext.Request.Path != new PathString("/Account/TwoFactorSignIn") || _httpContext.Request.Path != new PathString("/Account/AccessDenied"))
            {
                _httpContext.Items[".redirect"] = new PathString("/Account/TwoFactorSignIn");
                _httpContext.Request.Path = new PathString("/Account/TwoFactorSignIn");
            }
            else
            {
                //redirect to TwoFactorSignIn
            }
            return Task.FromResult(0);
        }
    }
}