namespace PermissionManagement.Models
{
    public class PermissionViewModel
    {
        public string RoleId { get; set; }
        public IList<RoleClaimsViewModel> RoleClaims { get; set; }
    }

    public class RoleClaimsViewModel
    {
        public String Type { get; set; }
        public string Value { get; set; }
        public bool Selected { get; set; }

    }
}
