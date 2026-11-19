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

        public DbSet<CanaryLogin> CanaryLogins => Set<CanaryLogin>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            var admin = new IdentityRole
            {
                Id = "6faa72bc-bc6b-48e8-977e-0e8b957296a4",
                Name = "Administrator",
                NormalizedName = "ADMINISTRATOR",
                ConcurrencyStamp = "be707c9a-918b-4301-bc39-420a433c7395"
            };
            var manager = new IdentityRole
            {
                Id = "5459c071-f7c9-4837-beb9-e187158d73e8",
                Name = "Manager",
                NormalizedName = "MANAGER",
                ConcurrencyStamp = "920af8bf-588e-48fd-a281-7db44a0c79fb"
            };
            var worker = new IdentityRole
            {
                Id = "15434d7f-16ae-45cb-bfec-10602b6fd200",
                Name = "Pracownik",
                NormalizedName = "PRACOWNIK",
                ConcurrencyStamp = "493d81ab-7e62-46b5-ad03-2e7fc1b3dc58"
            };
            var guest = new IdentityRole
            {
                Id = "1f87bb79-9b13-47b0-b4b5-6636804fe1eb",
                Name = "Gosc",
                NormalizedName = "GOSC",
                ConcurrencyStamp = "a3031f0f-b9a6-47b7-adca-589f0751e1c0"
            };
            
            builder.Entity<IdentityRole>().HasData(admin, manager, worker, guest);
        }

    }
}