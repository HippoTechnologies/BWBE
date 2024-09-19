using System.ComponentModel.DataAnnotations;

namespace BWBE.Bodies;

public class CookStepInit
{
    [MaxLength(255)] public string Description { get; set; } = null!;
    [MaxLength(36)] public string RecipeId { get; set; } = null!;

}