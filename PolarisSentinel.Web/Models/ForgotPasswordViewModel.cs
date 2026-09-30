using System.ComponentModel.DataAnnotations;

namespace PolarisSentinel.Web.Models
{
    //ViewModel for the forgot-password form; user submits email or username.
    public class ForgotPasswordViewModel
    {
        [Required(ErrorMessage ="Email or username is required.")]
        [Display(Name ="Email or Username")]
        public string? EmailOrUserName { get; set; }
    }
}
