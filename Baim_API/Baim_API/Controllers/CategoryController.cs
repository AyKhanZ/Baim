using DB.DbContexts;
using DB.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Baim_API.Controllers;
[ApiController]
[Route("Category")]
public class CategoryController : Controller
{  
	private readonly BaimContext _dbContext;

	public CategoryController(BaimContext dbContext)
	{
		_dbContext = dbContext;
	}

	// GET: api/Category
	[HttpGet("")]
	public async Task<ActionResult<List<Category>>> GetCategories()
	{
		var categories = await _dbContext.Categories
			//.Where(c => c.IsDeleted == false && c.Products!.Any())
			.ToListAsync();

		return Ok(categories);
	}

	// GET: api/Category/{id}
	[HttpGet("{id}")]
	public async Task<ActionResult<Category>> GetCategoryById(int id)
	{
		var category = await _dbContext.Categories.FindAsync(id);

		if (category == null) return NotFound();

		return Ok(category);
	}
}
