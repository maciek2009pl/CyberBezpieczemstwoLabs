// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;

namespace CyberBezpieczemstwoLab.Areas.Identity.Pages.Account
{

    [AllowAnonymous]
    public class LockoutModel : PageModel
    {
        public int RemainingSeconds { get; private set; }

        public void OnGet(DateTimeOffset? lockoutEnd)
        {
            if (lockoutEnd is DateTimeOffset end)
            {
                var remaining = end - DateTimeOffset.UtcNow;
                if (remaining > TimeSpan.Zero)
                {
                    RemainingSeconds = (int)remaining.TotalSeconds;
                }
            }
        }
    }
}
