using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using CyberBezpieczemstwoLab.Models;
using Microsoft.AspNetCore.Identity;

namespace CyberBezpieczemstwoLab
{
    public class ApplicationDbContext : IdentityDbContext<AppUsers>
    {
        public ApplicationDbContext (DbContextOptions<ApplicationDbContext> options) : base(options)
        {
            
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            var admin = new IdentityRole("Administrator");
            admin.NormalizedName = "ADMINISTRATOR";
            var manager = new IdentityRole("Manager");
            manager.NormalizedName = "MANAGER";
            var worker = new IdentityRole("Pracownik");
            worker.NormalizedName = "PRACOWNIK";
            var guest = new IdentityRole("Gosc");
            guest.NormalizedName = "GOSC";
            
            builder.Entity<IdentityRole>().HasData(admin, manager, worker, guest);
        }

    }
}