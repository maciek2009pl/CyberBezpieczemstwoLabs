using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace CyberBezpieczemstwoLab
{
    public class TurnstileService
    {
        public async Task<TurnstileVerificationResult> VerifyAsync(string token, string secret, string remoteIp)
        {
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(secret))
            {
                return new TurnstileVerificationResult { IsSuccess = false };
            }


            try
            {
                var fields = new Dictionary<string, string>
                {
                    ["secret"] = secret,
                    ["response"] = token
                };

                if (!string.IsNullOrWhiteSpace(remoteIp))
                {
                    fields["remoteip"] = remoteIp;
                }

                using var client = new HttpClient();
                using var response = await client.PostAsync(
                    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                    new FormUrlEncodedContent(fields));


                using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                var isSuccess = json.RootElement.TryGetProperty("success", out var success) &&
                                success.ValueKind == JsonValueKind.True;

                return new TurnstileVerificationResult { IsSuccess = isSuccess };
            }
             catch (Exception ex) when  (ex is HttpRequestException || ex is JsonException)
            {
                return new TurnstileVerificationResult { IsSuccess = false };
            }
        }
    }

    public class TurnstileVerificationResult
    {
        public bool IsSuccess {get; set; }
    }
}