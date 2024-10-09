using System.ComponentModel.DataAnnotations;

namespace BWBE.Models;

public class InventoryItem
{
    [MaxLength(36)] public string Id { get; set; } = null!;
    [MaxLength(50)] public string Name { get; set; } = null!;
    public int Quantity { get; set; }
    public int PurchaseQuantity { get; set; }
    public float CostPerPurchaseUnit { get; set; }
    [MaxLength(50)] public string Unit { get; set; } = null!;
    [MaxLength(250)] public string Notes { get; set; } = null!;
}