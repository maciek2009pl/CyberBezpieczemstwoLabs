// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;

using CyberBezpieczemstwoLab.Models;

namespace CyberBezpieczemstwoLab.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<AppUsers> _signInManager;
        private readonly UserManager<AppUsers> _userManager;
        private readonly CanaryLoginAlert _canaryLoginAlert;
        private readonly ILogger<LoginModel> _logger;
         [BindProperty]
        public InputModel Input { get; set; }
        public string ReturnUrl { get; set; }
        [TempData]
        public string ErrorMessage { get; set; }
        public LoginModel(
            SignInManager<AppUsers> signInManager,
            UserManager<AppUsers> userManager,
            CanaryLoginAlert canaryLoginAlert,
            ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _canaryLoginAlert = canaryLoginAlert;
            _logger = logger;
        }


        public class InputModel
        {
            [Required]
            public string Login { get; set; }
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }
            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
            public string Honeypot { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            string secret = "0x4AAAAAAFyViBfxA64QyMoY0ze2VDUfOBs";
            string clientIp = HttpContext.Connection.RemoteIpAddress.ToString();
            string browserChallengeToken = null;
            if (this.Request.Form.TryGetValue("cf-turnstile-response", out var hiddenFormField))
            {
                browserChallengeToken = hiddenFormField;
            }
            
            var turnstileApi = new TurnstileService();
            var verifyResult = await turnstileApi.VerifyAsync(browserChallengeToken, secret, clientIp);
            if (verifyResult.IsSuccess is false)
            {
                this.ModelState.AddModelError("captcha", "The Cloudflare challenge is not valid.");
                return new BadRequestResult();
            }

            returnUrl = Url.Content("~/");

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(Input.Login);
                if (user is not null &&
                    await _userManager.CheckPasswordAsync(user, Input.Password) &&
                    await HasExpiredTemporaryPasswordAsync(user))
                {
                    ModelState.AddModelError(
                        string.Empty,
                        "Temporary password has expired.");
                    return Page();
                }


                var result = await _signInManager.PasswordSignInAsync(Input.Login, Input.Password, Input.RememberMe, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    if(Input.Honeypot is not null)
                    {
                        ModelState.AddModelError(string.Empty, "Invalid login or password.");
                        return Page();
                    }

                    var userClaims = user is null
                        ? new List<Claim>()
                        : (await _userManager.GetClaimsAsync(user)).ToList();
                    if (userClaims.Any(claim =>
                            claim.Type == AppUsers.CanaryAccountClaimType &&
                            claim.Value == "true"))
                    {
                        await _canaryLoginAlert.SendCanaryUsedAsync(user.UserName);
                    }

                    if (userClaims.Any(claim =>
                            claim.Type == AppUsers.MustChangePasswordClaimType &&
                            claim.Value == "true"))
                    {
                        await _signInManager.SignOutAsync();


                        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(resetToken));
                        return RedirectToPage("./ResetPassword", new
                        {
                            code = encodedToken,
                            email = user.Email
                        });
                    }

                    _logger.LogInformation("User logged in.");
                    return LocalRedirect(returnUrl);
                }

                if (result.IsLockedOut)
                {
                    var lockedUser = await _userManager.FindByNameAsync(Input.Login);
                    return RedirectToPage("./Lockout", new { lockoutEnd = lockedUser.LockoutEnd });
                }

                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login or password.");
                    return Page();
                }
            }

            return Page();
        }

        private async Task<bool> HasExpiredTemporaryPasswordAsync(AppUsers user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            if (!userClaims.Any(claim =>
                    claim.Type == AppUsers.MustChangePasswordClaimType &&
                    claim.Value == "true"))
            {
                return false;
            }


            var expiryClaim = userClaims
                .FirstOrDefault(claim =>
                    claim.Type == AppUsers.TemporaryPasswordExpiresAtClaimType);
            if (expiryClaim is null)
            {
                return false;
            }


            return !DateTimeOffset.TryParse(
                       expiryClaim.Value,
                       CultureInfo.InvariantCulture,
                       DateTimeStyles.None,
                       out var expiresAt) ||
                   expiresAt <= DateTimeOffset.UtcNow;
        }

    }

    
}
