using System.ComponentModel.DataAnnotations;

namespace PolarisSentinel.Web.Models
{
    public class ChangePasswordViewModel
    {
        [Required(ErrorMessage = "Current password is required.")]
        [DataType(DataType.Password)]
        [Display(Name = "Current Password")]
        public string? CurrentPassword { get; set; }

        [Required(ErrorMessage = "New password is required.")]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        public string? NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare(nameof(NewPassword), ErrorMessage = "The passwords do not match.")]
        public string? ConfirmPassword { get; set; }
    }
}
