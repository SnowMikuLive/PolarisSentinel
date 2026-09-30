using System.ComponentModel.DataAnnotations;

namespace PolarisSentinel.Web.Models
{
    //ViewModel for the reset-password form.
    public class ResetPasswordViewModel
    {
        //Email carried over from the reset link; hidden field
        //从重置链接带过来的邮箱，隐藏字段
        [Required]
        //定义可空字符串属性Email,{get;set;}表示可读可写
        //Define the null string attribute Email, {get; set; } indicates readability and writing
        public string? Email { get; set; }

        // Token carried over from the reset link; hidden field
        //从重置链接带过来的token，隐藏字段
        [Required]
        //定义可空字符串属性，用来存放令牌，Code是重置令牌（token）
        public string? Code { get; set; }

        [Required(ErrorMessage ="New password is required.")]
        //指定这个是据类型是密码，页码上渲染成密码输入框（输入时显示圆点）
        [DataType(DataType.Password)]
        public string? NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        //比较特性，要求ConfirmPassword的值必须和NewPassword一致；如果不一致，显示错误信息“The passwords do not match.”
        [Compare(nameof(NewPassword), ErrorMessage = "The passwords do not match.")]
        public string? ConfirmPassword { get; set; }
    }
}
