using System;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;

namespace Mvc6Project.Models
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        public DateTime BirthDate { get; internal set; }
        public string Country { get; internal set; }
        public DateTime EmailLinkDate { get; internal set; }
        public string FirstName { get; internal set; }
        public DateTime JoinDate { get; internal set; }
        public DateTime LastLoginDate { get; internal set; }
        public string LastName { get; internal set; }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
         
        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }
       
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);
        }
    }
}
