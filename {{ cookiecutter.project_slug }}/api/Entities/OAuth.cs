using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace api.Entities;

public class OAuth
{
    [Key] 
    public Guid Id { get; set; }
    [MaxLength(255)]
    public string? GoogleId { get; set; }
    public string? GoogleRefreshToken { get; set; }
    
    public Guid UserId { get; set; }
    [ForeignKey("UserId")]
    public User? User { get; set; }
}