﻿using Microsoft.AspNetCore.Authorization;

namespace PermissionManagement.Permission
{
    internal class PermissionRequirement : IAuthorizationRequirement
    {
        public string Permission {  get; set; }
        public PermissionRequirement(string permission)
        {
            Permission = permission;
        }
    }
}
