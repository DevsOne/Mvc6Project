using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication.Facebook;
using Microsoft.AspNet.Authentication.Google;
using Microsoft.AspNet.Authentication.MicrosoftAccount;
using Microsoft.AspNet.Authentication.Twitter;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Diagnostics;
using Microsoft.AspNet.Diagnostics.Entity;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Routing;
using Microsoft.Data.Entity;
using Microsoft.Framework.Configuration;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using Microsoft.Framework.Logging.Console;
using Microsoft.Framework.Runtime;
using Mvc6Project.Models;
using Mvc6Project.Services;
using System.IO;
using System.Threading;
using System.Data.SqlClient;

namespace Mvc6Project
{
    public class Startup
    {

        private Timer threadingTimer;
        string connection = null;
        string command = null;
        string parameterName = null;
        string methodName = null;

        public Startup(IHostingEnvironment env, IApplicationEnvironment appEnv)
        {
            // Setup configuration sources.

            var builder = new ConfigurationBuilder(appEnv.ApplicationBasePath)
                .AddJsonFile("config.json")
                .AddJsonFile($"config.{env.EnvironmentName}.json", optional: true);

            if (env.IsDevelopment())
            {
                // This reads the configuration keys from the secret store.
                // For more details on using the user secret store see http://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets();
            }
            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
            connection = Configuration.Get("Data:DefaultConnection:ConnectionString");
            //StartTimer();
        }

        public IConfiguration Configuration { get; set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add Entity Framework services to the services container.
            services.AddEntityFramework()
                .AddSqlServer()
                .AddDbContext<ApplicationDbContext>(options =>
                    options.UseSqlServer(Configuration["Data:DefaultConnection:ConnectionString"]));

            // Add Identity services to the services container.
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
        
            
            // Configure the options for the authentication middleware.
            // You can add options for Google, Twitter and other middleware as shown below.
            // For more information see http://go.microsoft.com/fwlink/?LinkID=532715

            var appEnv = services.BuildServiceProvider().GetRequiredService<IApplicationEnvironment>();
            var configurationPath = Path.Combine(appEnv.ApplicationBasePath, "config.json");
            var configBuilder = new ConfigurationBuilder().AddJsonFile(configurationPath);
            var configuration = configBuilder.Build();


            services.Configure<FacebookAuthenticationOptions>(options =>
            {
                options.AppId = configuration.Get("AppSettings:FaceI");
                options.AppSecret = configuration.Get("AppSettings:FaceS");
                options.Scope.Add("public_profile");
                options.Scope.Add("user_birthday");
                options.Scope.Add("email");
                options.Notifications = new FacebookAuthenticationNotifications
                {
                    OnAuthenticated = async context =>
                    {
                        var identity = (System.Security.Claims.ClaimsIdentity)context.Principal.Identity;
                        identity.AddClaim(new System.Security.Claims.Claim("FacebookAccessToken", context.AccessToken));
                    }
                };
            });
            services.Configure<GoogleAuthenticationOptions>(options =>
            {
                options.ClientId = configuration.Get("AppSettings:GglI");
                options.ClientSecret = configuration.Get("AppSettings:GglS");
                options.Scope.Add("https://www.googleapis.com/auth/plus.login email");
                options.Notifications = new GoogleAuthenticationNotifications
                {
                    OnAuthenticated = async context =>
                    {
                        var identity = (System.Security.Claims.ClaimsIdentity)context.Principal.Identity;
                        identity.AddClaim(new System.Security.Claims.Claim("GoogleAccessToken", context.AccessToken));
                        foreach (var claim in context.User)
                        {
                            var claimType = string.Format("urn:google:{0}", claim.Key);
                            string claimValue = claim.Value.ToString();
                            if (!identity.HasClaim(claimType, claimValue))
                                identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Google"));
                        }
                    }
                };
            });
            services.Configure<TwitterAuthenticationOptions>(options =>
            {
                options.ConsumerKey = configuration.Get("AppSettings:TwtI");
                options.ConsumerSecret = configuration.Get("AppSettings:TwtS");

            });
            services.Configure<MicrosoftAccountAuthenticationOptions>(options =>
            {
                options.ClientId = configuration.Get("AppSettings:MsI");
                options.ClientSecret = configuration.Get("AppSettings:MsS");
                options.Scope.Add("wl.basic");
                options.Scope.Add("wl.emails");
                options.Scope.Add("wl.birthday");
                options.Notifications = new MicrosoftAccountAuthenticationNotifications
                {
                    OnAuthenticated = async context =>
                    {
                        var identity = (System.Security.Claims.ClaimsIdentity)context.Principal.Identity;
                        identity.AddClaim(new System.Security.Claims.Claim("MicrosoftAccessToken", context.AccessToken));
                        foreach (var claim in context.User)
                        {
                            var claimType = string.Format("urn:microsoft:{0}", claim.Key);
                            string claimValue = claim.Value.ToString();
                            if (!identity.HasClaim(claimType, claimValue))
                                identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, "XmlSchemaString", "Microsoft"));
                        }
                    }
                };
            });


            // Add MVC services to the services container.
            services.AddMvc();

            // Uncomment the following line to add Web API services which makes it easier to port Web API 2 controllers.
            // You will also need to add the Microsoft.AspNet.Mvc.WebApiCompatShim package to the 'dependencies' section of project.json.
            // services.AddWebApiConventions();

            // Register application services.
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();
        }

        // Configure is called after ConfigureServices is called.
        public async void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory, IServiceProvider serviceProvider,ApplicationDbContext context)
        {
            loggerFactory.MinimumLevel = LogLevel.Information;
            loggerFactory.AddConsole();

            // Configure the HTTP request pipeline.

            // Add the following to the request pipeline only in development environment.
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseErrorPage(ErrorPageOptions.ShowAll);
                app.UseDatabaseErrorPage(DatabaseErrorPageOptions.ShowAll);
            }
            else
            {
                // Add Error handling middleware which catches all application specific errors and
                // sends the request to the following path or controller action.
                app.UseErrorHandler("/Home/Error");
            }
            
            // Add static files to the request pipeline.
            app.UseStaticFiles();

            // Add cookie-based authentication to the request pipeline.
            app.UseIdentity();

            // Add authentication middleware to the request pipeline. You can configure options such as Id and Secret in the ConfigureServices method.
            // For more information see http://go.microsoft.com/fwlink/?LinkID=532715
            app.UseFacebookAuthentication();
            app.UseGoogleAuthentication();
            app.UseMicrosoftAccountAuthentication();
            app.UseTwitterAuthentication();
            // Add MVC to the request pipeline.
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");

                // Uncomment the following line to add a route for porting Web API 2 controllers.
                // routes.MapWebApiRoute("DefaultApi", "api/{controller}/{id?}");
            });
            //await CreateRoles(serviceProvider);
            await CreateRoles(context, serviceProvider);
        }

        //private async Task CreateRoles(IServiceProvider serviceProvider)
        //{
        //    var RoleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        //    var UserManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        //    string[] roleNames = { "Admin", "Member", "Moderator", "Junior", "Senior", "Candidate" };
        //    IdentityResult roleResult;
        //    foreach (var roleName in roleNames)
        //    {
        //        var roleExist = await RoleManager.RoleExistsAsync(roleName);
        //        if (!roleExist)
        //        {
        //            roleResult = await RoleManager.CreateAsync(new IdentityRole(roleName));
        //        }
        //    }
        //    var user = await UserManager.FindByIdAsync("deeb1ac9-072d-4e9f-b86d-a5d7144df46c");
        //    await UserManager.AddToRoleAsync(user, "Admin");

        //}

        private async Task CreateRoles(ApplicationDbContext context, IServiceProvider serviceProvider)
        {
            var UserManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var RoleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            List<IdentityRole> roles = new List<IdentityRole>();
            roles.Add(new IdentityRole { Name = "Admin", NormalizedName = "ADMIN" });
            roles.Add(new IdentityRole { Name = "Senior", NormalizedName = "SENIOR" });
            roles.Add(new IdentityRole { Name = "Moderator", NormalizedName = "MODERATOR" });
            roles.Add(new IdentityRole { Name = "Member", NormalizedName = "MEMBER" });
            roles.Add(new IdentityRole { Name = "Junior", NormalizedName = "JUNIOR" });
            roles.Add(new IdentityRole { Name = "Candidate", NormalizedName = "CANDIDATE" });
            foreach (var role in roles)
            {
                var roleExist = await RoleManager.RoleExistsAsync(role.Name);
                if (!roleExist)
                {
                    context.Roles.Add(role);
                    context.SaveChanges();
                }

            }

            var user = await UserManager.FindByIdAsync("deeb1ac9-072d-4e9f-b86d-a5d7144df46c");
            await UserManager.AddToRoleAsync(user, "Admin");
        }


        #region DeleteUser
        private void DeleteUserFromDatabase(string userid)
        {
            List<CommAndParams> commAndParam = new List<CommAndParams>();
            commAndParam.Add(new CommAndParams() { command = "DELETE FROM AspNetUserLogins WHERE UserId = @UserId", parameterName = "@UserId" });
            commAndParam.Add(new CommAndParams() { command = "DELETE FROM AspNetUserClaims WHERE UserId = @UserId", parameterName = "@UserId" });
            commAndParam.Add(new CommAndParams() { command = "DELETE FROM AspNetUserRoles WHERE UserId = @UserId", parameterName = "@UserId" });
            commAndParam.Add(new CommAndParams() { command = "DELETE FROM AspNetUsers WHERE Id = @Id", parameterName = "@Id" });
            foreach (var cap in commAndParam)
            {
                command = cap.command;
                parameterName = cap.parameterName;
                using (SqlConnection myConnection = new SqlConnection(connection))
                using (SqlCommand cmd = new SqlCommand(command, myConnection))
                {
                    cmd.Parameters.AddWithValue(parameterName, userid);
                    myConnection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.HasRows)
                        {
                            cmd.ExecuteNonQuery();
                            myConnection.Close();
                        }
                    }
                }
            }
        }

        private void DeleteUser()
        {
            using (SqlConnection myConnection = new SqlConnection(connection))
            using (SqlCommand cmd = new SqlCommand(command, myConnection))
            {
                cmd.Parameters.AddWithValue(parameterName, false);
                myConnection.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.HasRows)
                    {
                        // Read advances to the next row.
                        if (reader.Read())
                        {
                            if (methodName == "DeleteUncorfirmedAccounts")
                            {
                                DateTime emailLinkDate = (DateTime)reader["EmailLinkDate"];
                                if (emailLinkDate.AddMinutes(1) < DateTime.Now)
                                {
                                    DeleteById();
                                }
                            }
                            else if (methodName == "DeleteById")
                            {
                                string userid = reader["Id"].ToString();
                                DeleteUserFromDatabase(userid);
                            }
                        }
                        myConnection.Close();
                    }
                }
            }
        }

        private void DeleteById()
        {
            command = "SELECT Id AS Id FROM AspNetUsers WHERE EmailConfirmed = @EmailConfirmed";
            parameterName = "@EmailConfirmed";
            methodName = "DeleteById";
            DeleteUser();
        }
        private void DeleteUncorfirmedAccounts(object sender)
        {
            command = "SELECT EmailLinkDate AS EmailLinkDate FROM AspNetUsers WHERE EmailConfirmed = @EmailConfirmed";
            parameterName = "@EmailConfirmed";
            methodName = "DeleteUncorfirmedAccounts";
            DeleteUser();
        }

        private void StartTimer()
        {
            if (threadingTimer == null)
            {
                //raise timer callback 
                string str = DateTime.Now.ToLongTimeString(); threadingTimer = new Timer(new TimerCallback(DeleteUncorfirmedAccounts), str, 1000, 1000);
            }
        }
        #endregion DeleteUser
    }

    public class CommAndParams
    {
        public string command { get; set; }
        public string parameterName { get; set; }
    }
}
