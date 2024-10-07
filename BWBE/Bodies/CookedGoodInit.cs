using System.ComponentModel.DataAnnotations;

namespace BWBE.Models;

public class CookedGoodInit
{    
    [Key]   
    [MaxLength(36)] public string RecipeId { get; set; } = null!;
    public int Quantity { get; set; }

}