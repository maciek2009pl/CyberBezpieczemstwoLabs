using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace CyberBezpieczemstwoLab.Areas.Identity.Pages.Account
{
    [Authorize(Roles = "ADMINISTRATOR")]
    public class AdminPanel : PageModel
    {
        private readonly ILogger<AdminPanel> _logger;

        public AdminPanel(ILogger<AdminPanel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
        }
    }
}