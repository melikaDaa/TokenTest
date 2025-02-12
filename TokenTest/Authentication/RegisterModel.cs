using System.ComponentModel.DataAnnotations;

namespace TokenTest.Authentication
{
    public class RegisterModel
    {
        [Required(ErrorMessage ="لطفا این مقدار پر کنید")]
        public string UserName { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "لطفا این مقدار پر کنید")]
        public string Email { get; set; }
        [Required(ErrorMessage = "لطفا این مقدار پر کنید")]
        public string Password { get; set; }
    }
}
