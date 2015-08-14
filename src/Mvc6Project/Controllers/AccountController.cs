using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.Mvc.Rendering;
using Microsoft.Data.Entity;
using Microsoft.Framework.Configuration;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Runtime;
using Mvc6Project.Models;
using Mvc6Project.Services;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Facebook;

namespace Mvc6Project.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        #region Variables
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ISmsSender _smsSender;
        private readonly ApplicationDbContext _applicationDbContext;
        private static bool _databaseChecked;
        private static IApplicationEnvironment _hostingEnvironment;

        
        public static string EConfUser { get; set; }
        public static string connection = null;
        public static string command = null;
        public static string parameterName = null;
        public static string methodName = null;
        string codeType = null;

        public static string OEmail { get; set; }
        public static string OBirthday { get; set; }
        public static string OFname { get; set; }
        public static string OLname { get; set; }
        #endregion Variables

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ApplicationDbContext applicationDbContext,
            IApplicationEnvironment hostingEnvironment)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _applicationDbContext = applicationDbContext;
            _hostingEnvironment = hostingEnvironment;
            connection = GetConnectionString("DefaultConnection");
        }

        
        #region Login
        //
        // GET: /Account/Login
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            var custEmailConf = EmailConfirmation(model.LoginUsername);
            var custUserName = FindUserName(model.LoginUsername);
            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, set shouldLockout: true
            var result = await _signInManager.PasswordSignInAsync(model.LoginUsername, model.LoginPassword, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded && custEmailConf == false && custUserName != null)
            {
                _signInManager.SignOut();
                EConfUser = model.LoginUsername;
                return RedirectToAction("EmailConfirmationFailed", "Account");
            }
            else
            {
                ViewBag.ReturnUrl = returnUrl;
                if (ModelState.IsValid)
                {
                    if (result.Succeeded)
                    {
                        UpdateLastLoginDate(model.LoginUsername);
                        return RedirectToLocal(returnUrl);
                    }
                    if (result.RequiresTwoFactor)
                    {
                        return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                    }
                    if (result.IsLockedOut)
                    {
                        return View("Lockout");
                    }
                    else
                    {
                        ModelState.AddModelError("", "Invalid login attempt.");
                        return View("Login");
                    }
                }
                // If we got this far, something failed, redisplay form
                return View("Login");
            }
        }


        #endregion Login

        #region Register

        //
        // GET: /Account/Register
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var custEmail = FindEmail(model.RegisterEmail);
                var custUserName = FindUserName(model.RegisterUsername);
                var user = new ApplicationUser
                {
                    UserName = model.RegisterUsername,
                    Email = model.RegisterEmail,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    Country = model.Country,
                    BirthDate = model.BirthDate,
                    JoinDate = DateTime.Now,
                    EmailLinkDate = DateTime.Now,
                    LastLoginDate = DateTime.Now
                };
                if (custEmail == null && custUserName == null)
                {
                    var result = await _userManager.CreateAsync(user, model.RegisterPassword);
                    if (result.Succeeded)
                    {
                        await _userManager.AddToRoleAsync(user, "Candidate");
                        // Send an email with this link
                        //codeType = "EmailConfirmation";
                        //await SendEmail("ConfirmEmail", "Account", user, model.RegisterEmail, "WelcomeEmail", "Confirm your account");
                        return RedirectToAction("ConfirmationEmailSent", "Account");
                    }
                    AddErrors(result);
                }
                else
                {
                    if (custEmail != null)
                    {
                        ModelState.AddModelError("", "Email is already registered.");
                    }
                    if (custUserName != null)
                    {
                        ModelState.AddModelError("", "Username " + model.RegisterUsername.ToLower() + " is already taken.");
                    }
                }
            }
            // If we got this far, something failed, redisplay form
            return View("Register");
        }

        #endregion Register

        #region SendEmail

        public async Task SendEmail(string actionName, string controllerName, ApplicationUser user, string email, string emailTemplate, string emailSubject)
        {
            string code = null;
            if (codeType == "EmailConfirmation")
            {
                code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            }
            else if (codeType == "ResetPassword")
            {
                code = await _userManager.GeneratePasswordResetTokenAsync(user);
            }
            var callbackUrl = Url.Action(actionName, controllerName, new { userId = user.Id, date = DateTime.Now, code = code }, protocol: Context.Request.Scheme);
            var message = await EMailTemplate(emailTemplate);
            message = message.Replace("@ViewBag.Name", CultureInfo.CurrentCulture.TextInfo.ToTitleCase(user.FirstName));
            message = message.Replace("@ViewBag.Link", callbackUrl);

            AuthMessageSender sender = new AuthMessageSender(_hostingEnvironment);
            await sender.SendEmailAsync(email, emailSubject, message);
        }
        

        #endregion SendEmail

        #region SendTestMail

        [HttpGet]
        [AllowAnonymous]
        public ActionResult SendTestMail()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendTestMail(SendEMailViewModel model)
        {
            var message = await EMailTemplate("WelcomeEmail");
            message = message.Replace("@ViewBag.Name", CultureInfo.CurrentCulture.TextInfo.ToTitleCase(model.FirstName));

            AuthMessageSender sender = new AuthMessageSender(_hostingEnvironment);
            await sender.SendEmailAsync(model.Email, "Welcome!", message);
            return View("ConfirmationEmailSent");
        }
        #endregion SendTestMail

        #region ConfirmEmail
        // GET: /Account/ConfirmEmail
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, DateTime date, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return RedirectToAction("ConfirmationLinkExpired", "Account");
            }
            var emailConf = EmailConfirmationById(userId);
            if (emailConf == true)
            {
                return RedirectToAction("ConfirmationLinkUsed", "Account");
            }
            if (date != null)
            {
                if (date.AddMinutes(1) < DateTime.Now)
                {
                    return RedirectToAction("ConfirmationLinkExpired", "Account");
                }
                else
                {
                    var result = await _userManager.ConfirmEmailAsync(user, code);
                    return View(result.Succeeded ? "ConfirmEmail" : "Error");
                }
            }
            else
            {
                return View("Error");
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendConfirmationMail()
        {
            string res = null;
            string connection = GetConnectionString("DefaultConnection");
            using (SqlConnection myConnection = new SqlConnection(connection))
            using (SqlCommand cmd = new SqlCommand("SELECT Email AS Email FROM dbo.AspNetUsers WHERE UserName = @UserName", myConnection))
            {
                cmd.Parameters.AddWithValue("@UserName", EConfUser);
                myConnection.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.HasRows)
                    {
                        // Read advances to the next row.
                        if (reader.Read())
                        {
                            // To avoid unexpected bugs access columns by name.
                            res = reader["Email"].ToString();
                            var user = await _userManager.FindByEmailAsync(res);
                            UpdateEmailLinkDate(EConfUser);
                            codeType = "EmailConfirmation";
                            await SendEmail("ConfirmEmail", "Account", user, res, "WelcomeEmail", "Confirm your account");
                        }
                        myConnection.Close();
                    }
                }
            }
            return RedirectToAction("ConfirmationEmailSent", "Account");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult EmailConfirmationFailed()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ConfirmationEmailSent()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ConfirmationLinkExpired()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ConfirmationLinkUsed()
        {
            return View();
        }

        #endregion ConfirmEmail

        #region LogOff
        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult LogOff()
        {
            _signInManager.SignOut();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
        #endregion LogOff

        #region ExternalLogin
        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            EnsureDatabaseCreated(_applicationDbContext);
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        //
        // GET: /Account/ExternalLoginCallback
        [HttpGet]
        [Authorize]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null)
        {
            string userid = null;
            bool custEmailConf = false;
            string custUserName = null;
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("Index", "Home");
            }
            string userprokey = info.ProviderKey;
            userid = FindUserId(userprokey);
            if (userid != null)
            {
                custEmailConf = EmailConfirmationById(userid);
                custUserName = FindUserNameById(userid);
            }

            if (custEmailConf == false && custUserName != null)
            {
                EConfUser = custUserName;
                return RedirectToAction("EmailConfirmationFailed", "Account");
            }
            else
            {
                // Sign in the user with this external login provider if the user already has a login.
                var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
                if (result.Succeeded)
                {
                    UpdateLastLoginDate(custUserName);
                    return RedirectToLocal(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl });
                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    // If the user does not have an account, then ask the user to create an account.
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = info.LoginProvider;

                    if (info.LoginProvider == "Facebook")
                    {
                        var access_token = info.ExternalPrincipal.FindFirstValue("FacebookAccessToken");
                        var fb = new FacebookClient(access_token);

                        dynamic uEmail = fb.Get("/me?fields=email");
                        dynamic uBirthDate = fb.Get("/me?fields=birthday");
                        dynamic uFname = fb.Get("/me?fields=first_name");
                        dynamic uLname = fb.Get("/me?fields=last_name");
                        OEmail = uEmail.email;
                        OBirthday = uBirthDate.birthday;
                        OFname = uFname.first_name;
                        OLname = uLname.last_name;

                    }
                    else if (info.LoginProvider == "Google")
                    {
                        OEmail = info.ExternalPrincipal.FindFirstValue(ClaimTypes.Email);
                        OFname = info.ExternalPrincipal.FindFirst(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname").Value;
                        OLname = info.ExternalPrincipal.FindFirst(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname").Value;
                    }
                    else if (info.LoginProvider == "Microsoft")
                    {
                        string bday = info.ExternalPrincipal.FindFirst(c => c.Type == "urn:microsoft:birth_day").Value;
                        string bmonth = info.ExternalPrincipal.FindFirst(c => c.Type == "urn:microsoft:birth_month").Value;
                        string byear = info.ExternalPrincipal.FindFirst(c => c.Type == "urn:microsoft:birth_year").Value;

                        OEmail = info.ExternalPrincipal.FindFirstValue(ClaimTypes.Email);
                        OBirthday = bmonth + "/" + bday + "/" + byear;
                        OFname = info.ExternalPrincipal.FindFirst(c => c.Type == "urn:microsoft:first_name").Value;
                        OLname = info.ExternalPrincipal.FindFirst(c => c.Type == "urn:microsoft:last_name").Value;
                    }
                    else
                    {
                        OEmail = null;
                        OBirthday = null;
                        OFname = null;
                        OLname = null;
                    }

                    return View("ExternalLoginConfirmation");
                }
            }

        }



        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
        {
            if (User.IsSignedIn())
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var custEmail = FindEmail(model.Email);
                var custUserName = FindUserName(model.ExtUsername);
                var user = new ApplicationUser
                {
                    UserName = model.ExtUsername,
                    Email = model.Email,
                    FirstName = model.ExtFirstName,
                    LastName = model.ExtLastName,
                    Country = model.ExtCountry,
                    BirthDate = model.ExtBirthDate,
                    JoinDate = DateTime.Now,
                    EmailLinkDate = DateTime.Now,
                    LastLoginDate = DateTime.Now
                };

                if (custEmail == null && custUserName == null)
                {
                    var result = await _userManager.CreateAsync(user);
                    if (result.Succeeded)
                    {
                        await _userManager.AddToRoleAsync(user, "Candidate");
                        result = await _userManager.AddLoginAsync(user, info);
                        if (result.Succeeded)
                        {
                            codeType = "EmailConfirmation";
                            await SendEmail("ConfirmEmail", "Account", user, model.Email, "WelcomeEmail", "Confirm your account");
                            return RedirectToAction("ConfirmationEmailSent", "Account");
                        }
                    }
                    AddErrors(result);
                }
                else
                {
                    if (custEmail != null)
                    {
                        ModelState.AddModelError("", "Email is already registered.");
                    }
                    if (custUserName != null)
                    {
                        ModelState.AddModelError("", "Username " + model.ExtUsername.ToLower() + " is already taken.");

                    }
                }
            }

            ViewBag.ReturnUrl = returnUrl;
            return View("ExternalLoginConfirmation");
        }


        #endregion ExternalLogin

        #region ForgotPassword
        //
        // GET: /Account/ForgotPassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=532713
                // Send an email with this link
                //var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                //var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Context.Request.Scheme);
                //await _emailSender.SendEmailAsync(model.Email, "Reset Password",
                //   "Please reset your password by clicking here: <a href=\"" + callbackUrl + "\">link</a>");
                //return View("ForgotPasswordConfirmation");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }
        #endregion ForgotPassword

        #region ResetPassword
        //
        // GET: /Account/ResetPassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }
        #endregion ResetPassword

        #region SendCode
        //
        // GET: /Account/SendCode
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl = null, bool rememberMe = false)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }
            var userFactors = await _userManager.GetValidTwoFactorProvidersAsync(user);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }

            // Generate the token and send it
            var code = await _userManager.GenerateTwoFactorTokenAsync(user, model.SelectedProvider);
            if (string.IsNullOrWhiteSpace(code))
            {
                return View("Error");
            }

            var message = "Your security code is: " + code;
            if (model.SelectedProvider == "Email")
            {
                await _emailSender.SendEmailAsync(await _userManager.GetEmailAsync(user), "Security Code", message);
            }
            else if (model.SelectedProvider == "Phone")
            {
                await _smsSender.SendSmsAsync(await _userManager.GetPhoneNumberAsync(user), message);
            }

            return RedirectToAction(nameof(VerifyCode), new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }
        #endregion SendCode

        #region VerifyCode
        //
        // GET: /Account/VerifyCode
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyCode(string provider, bool rememberMe, string returnUrl = null)
        {
            // Require that the user has already logged in via username/password or external login
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes.
            // If a user enters incorrect codes for a specified amount of time then the user account
            // will be locked out for a specified amount of time.
            var result = await _signInManager.TwoFactorSignInAsync(model.Provider, model.Code, model.RememberMe, model.RememberBrowser);
            if (result.Succeeded)
            {
                return RedirectToLocal(model.ReturnUrl);
            }
            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError("", "Invalid code.");
                return View(model);
            }
        }
        #endregion VerifyCode

        #region Helpers

        // The following code creates the database and schema if they don't exist.
        // This is a temporary workaround since deploying database through EF migrations is
        // not yet supported in this release.
        // Please see this http://go.microsoft.com/fwlink/?LinkID=615859 for more information on how to do deploy the database
        // when publishing your application.
        private static void EnsureDatabaseCreated(ApplicationDbContext context)
        {
            if (!_databaseChecked)
            {
                _databaseChecked = true;
                context.Database.AsRelational().ApplyMigrations();
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private async Task<ApplicationUser> GetCurrentUserAsync()
        {
            return await _userManager.FindByIdAsync(Context.User.GetUserId());
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }



        public async Task<string> EMailTemplate(string template)
        {
            var templateFilePath = _hostingEnvironment.ApplicationBasePath + "\\wwwroot\\Templates\\" + template + ".cshtml";
            StreamReader objstreamreaderfile = new StreamReader(templateFilePath);
            var body = await objstreamreaderfile.ReadToEndAsync();
            objstreamreaderfile.Close();
            return body;
        }

        public string GetConnectionString(string connection)
        {
            var configurationPath = Path.Combine(_hostingEnvironment.ApplicationBasePath, "config.json");
            var configBuilder = new ConfigurationBuilder().AddJsonFile(configurationPath);
            var configuration = configBuilder.Build();
            string conOut = configuration.Get("Data:" + connection + ":ConnectionString");
            return conOut;
        }

        public static string ReturnString(string str)
        {
            string strOut = null;
            using (SqlConnection myConnection = new SqlConnection(connection))
            using (SqlCommand cmd = new SqlCommand(command, myConnection))
            {
                cmd.Parameters.AddWithValue(parameterName, str);
                myConnection.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.HasRows)
                    {
                        if (reader.Read())
                        {
                            if (methodName == "FindEmail")
                            {
                                strOut = reader["Email"].ToString();
                            }
                            else if (methodName == "FindUserName" || methodName == "FindUserNameById")
                            {
                                strOut = reader["UserName"].ToString();
                            }
                            else if (methodName == "FindUserId")
                            {
                                strOut = reader["UserId"].ToString();
                            }

                        }
                        myConnection.Close();
                    }
                    return strOut;
                }
            }
        }
        public static string FindEmail(string email)
        {
            command = "SELECT Email AS Email FROM AspNetUsers WHERE Email = @Email";
            parameterName = "@Email";
            methodName = "FindEmail";
            return ReturnString(email);
        }
        public string FindUserName(string username)
        {
            command = "SELECT UserName AS UserName FROM AspNetUsers WHERE UserName = @UserName";
            parameterName = "@UserName";
            methodName = "FindUserName";
            return ReturnString(username);
        }
        public string FindUserNameById(string userid)
        {
            command = "SELECT UserName AS UserName FROM AspNetUsers WHERE Id = @Id";
            parameterName = "@Id";
            methodName = "FindUserNameById";
            return ReturnString(userid);
        }
        public string FindUserId(string userprokey)
        {
            command = "SELECT UserId AS UserId FROM AspNetUserLogins WHERE ProviderKey = @ProviderKey";
            parameterName = "@ProviderKey";
            methodName = "FindUserId";
            return ReturnString(userprokey);
        }

        public bool ReturnBool(string str)
        {
            bool econfOut = false;
            string res = null;
            using (SqlConnection myConnection = new SqlConnection(connection))
            using (SqlCommand cmd = new SqlCommand(command, myConnection))
            {
                cmd.Parameters.AddWithValue(parameterName, str);
                myConnection.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.HasRows)
                    {
                        if (reader.Read())
                        {
                            res = reader["EmailConfirmed"].ToString();
                            if (res == "False")
                            {
                                econfOut = false;
                            }
                            else
                            {
                                econfOut = true;
                            }
                        }
                        myConnection.Close();
                    }
                    return econfOut;
                }
            }
        }
        public bool EmailConfirmation(string username)
        {
            command = "SELECT EmailConfirmed AS EmailConfirmed FROM AspNetUsers WHERE UserName = @UserName";
            parameterName = "@UserName";
            return ReturnBool(username);
        }
        public bool EmailConfirmationById(string userid)
        {
            command = "SELECT EmailConfirmed AS EmailConfirmed FROM AspNetUsers WHERE Id = @Id";
            parameterName = "@Id";
            return ReturnBool(userid);
        }

        public int UpdateDatabase(string username)
        {
            using (SqlConnection myConnection = new SqlConnection(connection))
            using (SqlCommand cmd = new SqlCommand(command, myConnection))
            {
                cmd.Parameters.AddWithValue(parameterName, username);
                myConnection.Open();
                return cmd.ExecuteNonQuery();
            }
        }
        public int UpdateEmailLinkDate(string username)
        {
            command = "UPDATE AspNetUsers SET EmailLinkDate = '" + DateTime.Now + "' WHERE UserName = @UserName";
            parameterName = "@UserName";
            return UpdateDatabase(username);
        }
        public int UpdateLastLoginDate(string username)
        {
            command = "UPDATE AspNetUsers SET LastLoginDate = '" + DateTime.Now + "' WHERE UserName = @UserName";
            parameterName = "@UserName";
            return UpdateDatabase(username);
        }
        
        public static IEnumerable<SelectListItem> GetCountries()
        {
            RegionInfo country = new RegionInfo(new CultureInfo("en-US", false).LCID);
            List<SelectListItem> countryNames = new List<SelectListItem>();
            string cult = CultureInfo.CurrentCulture.EnglishName;
            string count = cult.Substring(cult.IndexOf('(') + 1,
                             cult.LastIndexOf(')') - cult.IndexOf('(') - 1);
            //To get the Country Names from the CultureInfo installed in windows
            foreach (CultureInfo cul in CultureInfo.GetCultures(CultureTypes.SpecificCultures))
            {
                country = new RegionInfo(new CultureInfo(cul.Name, false).LCID);
                countryNames.Add(new SelectListItem()
                {
                    Text = country.DisplayName,
                    Value = country.DisplayName,
                    Selected = count == country.EnglishName
                });
            }
            //Assigning all Country names to IEnumerable
            IEnumerable<SelectListItem> nameAdded =
                countryNames.GroupBy(x => x.Text).Select(
                    x => x.FirstOrDefault()).ToList<SelectListItem>()
                    .OrderBy(x => x.Text);
            return nameAdded;
        }

        #endregion
    }
}
