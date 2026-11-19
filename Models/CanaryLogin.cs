using System.ComponentModel.DataAnnotations;

namespace CyberBezpieczemstwoLab.Models
{
    public class CanaryLogin
    {
        public int Id { get; set; }
        [Required]
        [MaxLength(256)]
        public string UserName { get; set; } = string.Empty;
        public DateTimeOffset CanaryAtDate { get; set; }
    }
}
