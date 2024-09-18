using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace BWBE.Models;

public class CookStep
{
    [MaxLength(255)] public string Description { get; set; } = null!;
    [MaxLength(36)] public string RecipeId { get; set; } = null!;

    public int Id { get; set; }
}