namespace DB.Models;

public class Product
{
	public int Id { get; set; }
	public string? Id1C { get; set; }
	public string Name { get; set; }
	public string? Description { get; set; }
	public int Price { get; set; }
	public byte[]? Image { get; set; }
	public bool? IsFlagman { get; set; } // Для карусели вип продуктов 
	public bool? IsPublic { get; set; } // Для приватности 
	public bool? IsDeleted { get; set; }

	public int CategoryId { get; set; }
	public Category Category { get; set; }
}