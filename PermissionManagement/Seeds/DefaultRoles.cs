﻿using Microsoft.AspNetCore.Identity;
using PermissionManagement.Constants;

namespace PermissionManagement.Seeds
{
    public class DefaultRoles
    {
        public static async Task SeedAsync(UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager)
        {
            await roleManager.CreateAsync(new IdentityRole(Roles.Administration.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Roles.Manager.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Roles.Developer.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Roles.Maintainer.ToString()));
        }
    }
}
