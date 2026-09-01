using System.ComponentModel.DataAnnotations;

namespace PolarisSentinel.Web.Models
{
    //Login View model
    public class LoginViewModel
    {
        //Username
        [Required(ErrorMessage = "Username is required.")]
        [Display(Name= "Username")]
        public string? Username { get; set; }

        //Password
        [Required(ErrorMessage="Password is required.")]
        [DataType(DataType.Password)]
        [Display(Name="Password")]
        public string? Password { get; set; }

    }
}
