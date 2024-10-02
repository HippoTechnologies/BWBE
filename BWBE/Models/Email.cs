using System.ComponentModel.DataAnnotations;

namespace BWBE.Models;

public class Email
{
    [MaxLength(36)] public string Id { get; set; } = null!;
    [MaxLength(36)] public string UserId { get; set; } = null!;
    
    [MaxLength(50)] public string Address { get; set; } = null!;
    
    public bool Verified { get; set; }
}