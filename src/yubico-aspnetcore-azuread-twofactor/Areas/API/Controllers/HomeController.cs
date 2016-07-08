using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace yubicoaspnetcoreazureadtwofactor.Areas.API.Controllers
{
    [Authorize(Policy="YubiKeyOTP")]
    [Area("API")]
    public class HomeController : Controller
    {
        // GET: /<controller>/
        public IActionResult Index()
        {
            ViewData["Message"] = "Your application area demo page.";
            return View();
        }
        public IActionResult Error(string message)
        {
            ViewBag.Message = message;
            return View();
        }
    }
}
