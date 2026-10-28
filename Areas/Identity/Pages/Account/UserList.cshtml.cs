using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Net.Sockets;
using System.Security.Claims;
using CyberBezpieczemstwoLab.Models;
using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MimeKit;
using PasswordGenerator;

namespace CyberBezpieczemstwoLab.Areas.Identity.Pages.Account
{
    [Authorize(Roles = "Administrator, Manager")]
    public class UserList : PageModel
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly UserManager<AppUsers> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<UserList> _logger;

        public UserList(
            ApplicationDbContext dbContext,
            UserManager<AppUsers> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ILogger<UserList> logger)
        {
            _dbContext = dbContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _logger = logger;
        }

        [BindProperty]
        public EditUserInput Input { get; set; } = new();

        [BindProperty]
        public AddUserInput NewUser { get; set; } = new();

        public IList<(string Id, string? Login, string? Email, IList<string> Roles)> Users { get; private set; } = [];

        public IList<string> AvailableRoles { get; private set; } = [];

        public bool ShowEditModal { get; private set; }

        public bool ShowAddModal { get; private set; }

        [TempData]
        public string? StatusMessage { get; set; }

        public async Task OnGetAsync()
        {
            await LoadUsersAsync();
        }

        public async Task<IActionResult> OnPostUpdateAsync()
        {
            RemoveModelStateFor(nameof(NewUser));
            if (!ModelState.IsValid)
            {
                return await RedisplayAsync();
            }

            var user = await _userManager.FindByIdAsync(Input.UserId);
            if (user is null)
            {
                return NotFound();
            }

            string[] requestedRoles = string.IsNullOrEmpty(Input.Role) ? [] : [Input.Role];
            var validRoles = await GetAvailableRolesAsync();
            if (requestedRoles.Except(validRoles, StringComparer.Ordinal).Any())
            {
                ModelState.AddModelError(nameof(Input.Role), "Select a role.");
                return await RedisplayAsync();
            }

            var currentRoles = await _userManager.GetRolesAsync(user);
            var rolesToRemove = currentRoles.Except(requestedRoles, StringComparer.Ordinal).ToArray();
            var rolesToAdd = requestedRoles.Except(currentRoles, StringComparer.Ordinal).ToArray();

            await using var transaction = await _dbContext.Database.BeginTransactionAsync();

            user.UserName = Input.Login.Trim();
            user.Email = Input.Email.Trim();
            var updateResult = await _userManager.UpdateAsync(user);
            var succeeded = AddIdentityErrors(updateResult);

            if (succeeded && rolesToRemove.Length > 0)
            {
                succeeded = AddIdentityErrors(await _userManager.RemoveFromRolesAsync(user, rolesToRemove));
            }

            if (succeeded && rolesToAdd.Length > 0)
            {
                succeeded = AddIdentityErrors(await _userManager.AddToRolesAsync(user, rolesToAdd));
            }
            await transaction.CommitAsync();
            StatusMessage = "User updated successfully.";
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostAddAsync()
        {
            ModelState.Clear();
            if (!TryValidateModel(NewUser, nameof(NewUser)))
            {
                return await RedisplayAddUserAsync();
            }

            var validRoles = await GetAvailableRolesAsync();
            if (!validRoles.Contains(NewUser.Role, StringComparer.Ordinal))
            {
                ModelState.AddModelError($"{nameof(NewUser)}.{nameof(NewUser.Role)}", "Select a role.");
                return await RedisplayAddUserAsync();
            }

            var pwd = new Password(includeLowercase: true, includeUppercase: true, 
                includeNumeric: true, includeSpecial: true, passwordLength: 16);
            var password = pwd.Next();
            var passwordExpiresAt = DateTimeOffset.UtcNow.AddHours(12);
            
            var user = new AppUsers
            {
                UserName = NewUser.Login.Trim(),
                Email = NewUser.Email.Trim(),
            };

            await using var transaction = await _dbContext.Database.BeginTransactionAsync();
            var createResult = await _userManager.CreateAsync(user, password);
            if (!AddIdentityErrors(createResult))
            {
                await transaction.RollbackAsync();
                return await RedisplayAddUserAsync();
            }

            var roleResult = await _userManager.AddToRoleAsync(user, NewUser.Role);
            if (!AddIdentityErrors(roleResult))
            {
                await transaction.RollbackAsync();
                return await RedisplayAddUserAsync();
            }

            var claimResult = await _userManager.AddClaimAsync(
                user,
                new Claim(AppUsers.MustChangePasswordClaimType, "true"));
            if (!AddIdentityErrors(claimResult))
            {
                await transaction.RollbackAsync();
                return await RedisplayAddUserAsync();
            }

            var expiryClaimResult = await _userManager.AddClaimAsync(
                user,
                new Claim(
                    AppUsers.TemporaryPasswordExpiresAtClaimType,
                    passwordExpiresAt.ToString("O", CultureInfo.InvariantCulture)));
            if (!AddIdentityErrors(expiryClaimResult))
            {
                await transaction.RollbackAsync();
                return await RedisplayAddUserAsync();
            }


            await SendGeneratedPasswordEmailAsync(user.Email!, password, passwordExpiresAt);
            await transaction.CommitAsync();
            StatusMessage = "User created successfully.";
            return RedirectToPage();
        }

        private async Task SendGeneratedPasswordEmailAsync(
            string recipient,
            string password,
            DateTimeOffset passwordExpiresAt)
        {
            var host = _configuration["Smtp:Host"] ?? "localhost";
            var port = _configuration.GetValue<int?>("Smtp:Port") ?? 1025;
            var sender = _configuration["Smtp:From"] ?? "cyber@localhost";

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("CyberBezpieczemstwoLab", sender));
            message.To.Add(MailboxAddress.Parse(recipient));
            message.Subject = "New generated password:";
            message.Body = new TextPart("plain")
            {
                Text = $"Your password is: {password}\n\nPassword is valid until {passwordExpiresAt.ToLocalTime():g}."
            };

            using var smtpClient = new SmtpClient();
            await smtpClient.ConnectAsync(host, port, SecureSocketOptions.None);
            await smtpClient.SendAsync(message);
            await smtpClient.DisconnectAsync(true);
        }

        public async Task<IActionResult> OnPostRemoveAsync(string userId)
        {
            if (User.Identity?.IsAuthenticated != true)
            {
                return Challenge();
            }

            if (!User.IsInRole("Administrator"))
            {
                return Forbid();
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return NotFound();
            }

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                AddIdentityErrors(result);
                await LoadUsersAsync();
                return Page();
            }

            StatusMessage = "User removed successfully.";
            return RedirectToPage();
        }

        private async Task<IActionResult> RedisplayAsync()
        {
            RemoveModelStateFor(nameof(NewUser));
            ShowEditModal = true;
            await LoadUsersAsync();
            return Page();
        }

        private async Task<IActionResult> RedisplayAddUserAsync()
        {
            RemoveModelStateFor(nameof(Input));
            ShowAddModal = true;
            await LoadUsersAsync();
            return Page();
        }

        private void RemoveModelStateFor(string prefix)
        {
            foreach (var key in ModelState.Keys
                         .Where(key => key.StartsWith($"{prefix}.", StringComparison.Ordinal))
                         .ToArray())
            {
                ModelState.Remove(key);
            }
        }

        private async Task LoadUsersAsync()
        {
            AvailableRoles = await GetAvailableRolesAsync();
            var users = await _userManager.Users
                .OrderBy(user => user.UserName)
                .ToListAsync();

            var userList = new List<(string Id, string? Login, string? Email, IList<string> Roles)>(users.Count);
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userList.Add((user.Id, user.UserName, user.Email, roles));
            }

            Users = userList;
        }

        private async Task<IList<string>> GetAvailableRolesAsync()
        {
            return await _roleManager.Roles
                .Where(role => role.Name != null)
                .Select(role => role.Name!)
                .ToListAsync();
        }

        private bool AddIdentityErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return result.Succeeded;
        }

        public sealed class EditUserInput
        {
            [Required]
            public string UserId { get; set; } = string.Empty;

            [Required]
            [StringLength(256)]
            public string Login { get; set; } = string.Empty;

            [Required]
            [EmailAddress]
            [StringLength(256)]
            public string Email { get; set; } = string.Empty;

            public string? Role { get; set; }
        }

        public sealed class AddUserInput
        {
            [Required]
            [StringLength(256)]
            public string Login { get; set; } = string.Empty;

            [Required]
            [EmailAddress]
            [StringLength(256)]
            public string Email { get; set; } = string.Empty;

            [Required]
            public string Role { get; set; } = string.Empty;
        }
    }
}
