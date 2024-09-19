using System.ComponentModel.DataAnnotations;

namespace BWBE.Models;

public class CookStepDelete
{
    [MaxLength(36)] public string RecipeId { get; set; } = null!;
    public int Id { get; set; }
}