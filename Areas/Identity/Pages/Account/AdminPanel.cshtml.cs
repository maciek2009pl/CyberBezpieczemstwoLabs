using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using CyberBezpieczemstwoLab.Models;

namespace CyberBezpieczemstwoLab.Areas.Identity.Pages.Account
{
    [Authorize(Roles = "Administrator")]
    public class AdminPanel : PageModel
    {
        private readonly ApplicationDbContext _dbContext;

        public AdminPanel(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public IList<AppUsers> CanaryAccounts { get; private set; } = [];

        public async Task OnGetAsync()
        {
            CanaryAccounts = await _dbContext.Users
                .Where(user => _dbContext.UserClaims.Any(claim =>
                    claim.UserId == user.Id &&
                    claim.ClaimType == AppUsers.CanaryAccountClaimType &&
                    claim.ClaimValue == "true"))
                .OrderBy(user => user.UserName)
                .ToListAsync();
        }
        
    }
}