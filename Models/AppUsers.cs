using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace CyberBezpieczemstwoLab.Models
{
    public class AppUsers : IdentityUser
    {
        public const string MustChangePasswordClaimType = "MustChangePassword";
        public const string TemporaryPasswordExpiresAtClaimType = "TemporaryPasswordExpiresAt";
        public const string CanaryAccountClaimType = "CanaryAccount";
    }
}