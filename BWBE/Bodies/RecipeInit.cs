using System.ComponentModel.DataAnnotations;

namespace BWBE.Bodies;

public class RecipeInit
{
    [MaxLength(50)] public string Name { get; set; } = null!;
    [MaxLength(255)] public string Description { get; set; } = null!;
    [MaxLength(50)] public string PrepUnit { get; set; } = null!;
    [MaxLength(50)] public string CookUnit { get; set; } = null!;




    public float Rating { get; set; }
    public float PrepTime { get; set; }
    public float CookTime { get; set; }
}