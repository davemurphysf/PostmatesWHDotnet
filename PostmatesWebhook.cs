using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace Postmates.Demo
{
    public static class PostmatesWebhook
    {
        [FunctionName("PostmatesWebhook")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            if (!req.Headers.ContainsKey("X-Postmates-Signature"))
            {
                return new BadRequestResult();
            }

            var headerValue = req.Headers["X-Postmates-Signature"].ToString();

            if (string.IsNullOrEmpty(headerValue))
            {
                return new BadRequestResult();
            }

            var secret = System.Environment.GetEnvironmentVariable("PM_WEBHOOK_SECRET", EnvironmentVariableTarget.Process);

            if (string.IsNullOrEmpty(secret))
            {
                return new StatusCodeResult(500);
            }

            var body = await req.ReadAsStringAsync();

            var encoding = new UTF8Encoding();

            var requestBytes = encoding.GetBytes(body);

            Byte[] hashBytes;

            using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret)))
            {
                hashBytes = hmac.ComputeHash(requestBytes);
            }

            if (!headerValue.Equals(BitConverter.ToString(hashBytes).Replace("-", ""), StringComparison.OrdinalIgnoreCase))
            {
                return new BadRequestResult();
            }
            else
            {
                return new OkResult();
            }
        }
    }
}
