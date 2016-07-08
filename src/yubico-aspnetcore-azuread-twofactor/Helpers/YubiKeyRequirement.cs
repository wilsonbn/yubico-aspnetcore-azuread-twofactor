using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace yubicoaspnetcoreazureadtwofactor.Helpers
{
    internal class YubiKeyRequirement : IAuthorizationRequirement
    {
        public bool YubiKeyUser(ISession session)
        {
            return session.IsAvailable && session.Keys.Contains("YubicoClientStatus") && session.GetString("YubicoClientStatus").Equals("Ok");
        }
    }
}