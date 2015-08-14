using Microsoft.Framework.Configuration;
using Microsoft.Framework.Runtime;
using System;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;


namespace Mvc6Project.Services
{
    // This class is used by the application to send Email and SMS
    // when you turn on two-factor authentication in ASP.NET Identity.
    // For more details see this link http://go.microsoft.com/fwlink/?LinkID=532713
    public class AuthMessageSender : IEmailSender, ISmsSender
    {
        IApplicationEnvironment _appEnv;
        
        public AuthMessageSender(IApplicationEnvironment appEnv)
        {
            _appEnv = appEnv;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            try
            {
                var configurationPath = Path.Combine(_appEnv.ApplicationBasePath, "config.json");
                var configBuilder = new ConfigurationBuilder().AddJsonFile(configurationPath);
                var configuration = configBuilder.Build();



                var _email = "devsonetest@hotmail.com";
                var _epass = configuration.Get("AppSettings:EmailPassword");
                var _dispName = "Devsone";
                MailMessage myMessage = new MailMessage();
                myMessage.To.Add(email);
                myMessage.From = new MailAddress(_email, _dispName);
                myMessage.Subject = subject;
                myMessage.Body = message;
                myMessage.IsBodyHtml = true;

                using (SmtpClient smtp = new SmtpClient())
                {
                    smtp.EnableSsl = true;
                    smtp.Host = "smtp.live.com";
                    smtp.Port = 587;
                    smtp.UseDefaultCredentials = false;
                    smtp.Credentials = new NetworkCredential(_email, _epass);
                    smtp.DeliveryMethod = SmtpDeliveryMethod.Network;
                    smtp.SendCompleted += (s, e) => { smtp.Dispose(); };
                    await smtp.SendMailAsync(myMessage);
                }
            }
            catch (Exception ex)
            {

                throw ex;
            }

        }


        public Task SendSmsAsync(string number, string message)
        {
            // Plug in your SMS service here to send a text message.
            return Task.FromResult(0);
        }
    }
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
    }

    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}
