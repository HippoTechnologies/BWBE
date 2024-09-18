using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace BWBE.Models;

public class CookStepDelete
{
    [MaxLength(36)] public string RecipeId { get; set; } = null!;
    public int Id { get; set; }
}