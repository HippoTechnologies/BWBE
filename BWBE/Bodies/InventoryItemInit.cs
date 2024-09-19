namespace BWBE.Bodies;

public class InventoryItemInit
{
    public string Name { get; set; } = null!;
    public int Quantity { get; set; }
    public int PurchaseQuantity { get; set; }
    public float CostPerPurchaseUnit { get; set; }
    public string Unit { get; set; } = null!;
    public string Notes { get; set; } = null!;
}