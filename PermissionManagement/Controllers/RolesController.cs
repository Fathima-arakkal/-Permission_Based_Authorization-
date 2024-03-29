﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace PermissionManagement.Controllers
{
    [Authorize(Roles = "Administration")]
    public class RolesController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        public RolesController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
        [HttpGet]
        public async Task<IActionResult> Index()

        {
            var roles = await _roleManager.Roles.ToListAsync();
            return View(roles);
        }
        [HttpPost]
        public async Task<IActionResult>AddRole(String roleName)
        {
            if(roleName !=null)
            {
                await _roleManager.CreateAsync(new IdentityRole(roleName.Trim()));  

            }
            return RedirectToAction("Index");
        }
    }
}
