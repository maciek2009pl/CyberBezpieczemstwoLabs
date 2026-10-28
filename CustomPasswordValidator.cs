using Microsoft.AspNetCore.Identity;
using CyberBezpieczemstwoLab.Models;

namespace CyberBezpieczemstwoLab
{
    public class CustomPasswordValidator : IPasswordValidator<AppUsers>
    {
        private readonly IPasswordHasher<AppUsers> _passwordHasher;

        public CustomPasswordValidator(IPasswordHasher<AppUsers> passwordHasher)
        {
            _passwordHasher = passwordHasher;
        }

        public Task<IdentityResult> ValidateAsync(
            UserManager<AppUsers> manager,
            AppUsers user,
            string? password)
        {
            if (!string.IsNullOrEmpty(password) &&
                !string.IsNullOrEmpty(user.PasswordHash) &&
                _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password) !=
                PasswordVerificationResult.Failed)
            {
                return Task.FromResult(
                    IdentityResult.Failed(
                        new IdentityError
                        {
                            Code = "PasswordReuse",
                            Description = "Cant reuse a password."
                        }));
            }

            if (!string.IsNullOrEmpty(password) &&
                !string.IsNullOrEmpty(user.UserName) &&
                password.Contains(
                    user.UserName,
                    StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(
                    IdentityResult.Failed(
                        new IdentityError
                        {
                            Code = "PasswordContainsUsername",
                            Description = "Password cannot contain the username."
                        }));
            }
            return Task.FromResult(IdentityResult.Success);
        }
    }
}