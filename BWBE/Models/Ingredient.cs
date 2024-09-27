using System.ComponentModel.DataAnnotations;

namespace BWBE.Models;

public class Ingredient
{
    public int Id { get; set; }
    [MaxLength(36)] public string RecipeId { get; set; } = null!;
    [MaxLength(36)] public string InventoryId { get; set; } = null!;
    [MaxLength(50)] public string Name { get; set; } = null!;
    public int Quantity { get; set; }
    public int MinQuantity { get; set; }
    [MaxLength(50)] public string Unit { get; set; } = null!;
}