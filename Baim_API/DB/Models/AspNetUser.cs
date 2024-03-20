using Microsoft.AspNetCore.Identity; 

namespace DB.Models;
public enum TaskState
{
	None, // Ничего
	CurrentlyDoing, // Делаю
	Helping, // Помогаю
	Delegated, // Поручать 
	Supervising // Наблюдаю
}

public partial class AspNetUser : IdentityUser
{
	// Clients & Employers
	public string? Id1C { get; set; }
	public int? Age { get; set; }
	public byte[]? Image { get; set; }
	public string? Description { get; set; } 
	public TaskState? TaskState { get; set; }  
		
	public virtual ICollection<AspNetUserClaim> AspNetUserClaims { get; set; } = new List<AspNetUserClaim>();
	public virtual ICollection<AspNetUserLogin> AspNetUserLogins { get; set; } = new List<AspNetUserLogin>();
	public virtual ICollection<AspNetUserToken> AspNetUserTokens { get; set; } = new List<AspNetUserToken>();
	public virtual ICollection<AspNetRole> Roles { get; set; } = new List<AspNetRole>();
	public virtual ICollection<Order>? Orders { get; set; } = new List<Order>();

	public Client? Client { get; set; }
	public int? ClientId { get; set; }

	public Employer? Employer { get; set; }
	public int? EmployerId { get; set; } 
} 