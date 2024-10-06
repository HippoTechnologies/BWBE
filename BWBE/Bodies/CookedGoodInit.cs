using System.ComponentModel.DataAnnotations;

namespace BWBE.Models;

public class CookedGoodInit
{
    [MaxLength(50)] public string Name { get; set; } = null!;
    
    [Key]   
    [MaxLength(36)] public string RecipeId { get; set; } = null!;
    public int Quantity { get; set; }

}