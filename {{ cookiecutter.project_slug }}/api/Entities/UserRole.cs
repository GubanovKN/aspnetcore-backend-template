using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace api.Entities;

public class UserRole
{
    [Key]
    public Guid Id { get; set; }
    
    public Guid UserId { get; set; }
    [ForeignKey("UserId")]
    public User? User { get; set; }
    
    public Guid RoleId { get; set; }
    [ForeignKey("RoleId")]
    public Role? Role { get; set; }
}