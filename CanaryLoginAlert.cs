using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using MimeKit;

namespace CyberBezpieczemstwoLab
{
    public class CanaryLoginAlert
    {
        private readonly IConfiguration _configuration;

        public CanaryLoginAlert(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendCanaryUsedAsync(string login)
        {
            var host = _configuration["Smtp:Host"] ?? "localhost";
            var port = _configuration.GetValue<int?>("Smtp:Port") ?? 1025;
            var sender = _configuration["Smtp:From"] ?? "cyber@localhost";

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("CyberBezpieczemstwoLab", sender));
            message.To.Add(MailboxAddress.Parse("CyberBezpieczemstwoLabAdmin@gmail.com"));
            message.Subject = "Canary account login detected";
            message.Body = new TextPart("plain")
            {
                Text = $"Canary account used: {login}"
            };
            using var smtpClient = new SmtpClient();
            await smtpClient.ConnectAsync(host, port, SecureSocketOptions.None);
            await smtpClient.SendAsync(message);
            await smtpClient.DisconnectAsync(true);
        }
    }
}
