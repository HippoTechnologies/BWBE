using System.ComponentModel.DataAnnotations;

namespace BWBE.Models;

public class Ingredient
{
    public int ID { get; set; }
    [MaxLength(36)] public string RecipeID { get; set; } = null!;
    [MaxLength(36)] public string InventoryID { get; set; } = null!;
    [MaxLength(50)] public string Name { get; set; } = null!;
    public int Quantity { get; set; }
    public int MinQuantity { get; set; }
    [MaxLength(50)] public string Unit { get; set; } = null!;
}