using DB.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace DB.DbContexts;
public class BaimContext : IdentityDbContext<AspNetUser, IdentityRole, string>
{
	public DbSet<Category> Categories { get; set; }
	public DbSet<Product> Products { get; set; }
	public DbSet<Order> Orders { get; set; }
	public DbSet<OrderProduct> OrderProducts { get; set; }
	public DbSet<Client> Clients { get; set; }
	public DbSet<Employer> Employers { get; set; }
	public DbSet<AspNetUser> Users { get; set; }
	public BaimContext(DbContextOptions<BaimContext> options)
		: base(options)
	{ }

	protected override void OnModelCreating(ModelBuilder builder)
	{ 
		builder.Entity<Category>(entity =>
		{
			entity.HasKey(c => c.Id);
			entity.Property(c => c.Id).ValueGeneratedOnAdd();
			entity.Property(c => c.Name).IsRequired().HasMaxLength(25);
			entity.Property(c => c.IsDeleted).HasDefaultValue(false); 

			entity.HasIndex(c => c.Name).IsUnique(); 
		});

		builder.Entity<Product>(entity =>
		{
			entity.HasKey(p => p.Id);
			entity.Property(p => p.Id).ValueGeneratedOnAdd();
			entity.Property(p => p.Id1C).HasMaxLength(50);
			entity.Property(p => p.Name).IsRequired().HasMaxLength(50);
			entity.Property(p => p.Description).HasMaxLength(200);
			entity.Property(p => p.Price).IsRequired();
			entity.Property(p => p.Image);
			entity.Property(p => p.IsFlagman).HasDefaultValue(false);
			entity.Property(p => p.IsPublic).HasDefaultValue(false);
			entity.Property(p => p.IsDeleted).HasDefaultValue(false);

			entity.HasOne(p => p.Category)
				.WithMany(c => c.Products)
				.HasForeignKey(p => p.CategoryId)
				.OnDelete(DeleteBehavior.Restrict);
		});

		builder.Entity<Order>(entity =>
		{
			entity.HasKey(o => o.Id);
			entity.Property(o => o.Id).ValueGeneratedOnAdd();
			entity.Property(o => o.StartDate);
			entity.Property(o => o.DoneDate);
			entity.Property(o => o.TotalPrice);
			entity.Property(o => o.PaymentMethod);

			entity.Property(o => o.TotalPrice).IsRequired();

			entity.HasOne(o => o.User)
				.WithMany(u => u.Orders)
				.HasForeignKey(o => o.UserId);
		});

		builder.Entity<OrderProduct>(entity =>
		{
			entity.HasKey(op => op.Id);
			entity.Property(op => op.Id).ValueGeneratedOnAdd();

			entity.HasOne(op => op.Order)
				.WithMany(o => o.OrderProducts)
				.HasForeignKey(op => op.OrderId);
		});

		builder.Entity<Client>(entity =>
		{
			entity.HasKey(op => op.Id);
			entity.Property(op => op.Id).ValueGeneratedOnAdd();
			entity.Property(с => с.IsPublic).HasDefaultValue(false);
			entity.Property(с => с.ClientFeedback);
			entity.Property(с => с.ClientConfirm);
			entity.Property(с => с.YoutubeLink); 
		});

		builder.Entity<Employer>(entity =>
		{
			entity.HasKey(op => op.Id);
			entity.Property(op => op.Id).ValueGeneratedOnAdd();
			entity.Property(e => e.Position).IsRequired().HasMaxLength(50);
			entity.Property(e => e.Experience).IsRequired();
			entity.Property(e => e.Certificates);
		});

		builder.Entity<AspNetUser>(entity =>
		{ 
			entity.HasKey(u => u.Id);
			entity.Property(u => u.Age); 
			entity.Property(u => u.Image); 
			entity.Property(u => u.Description); 
			entity.Property(u => u.TaskState); 
			entity.Property(u => u.PhoneNumber);

			entity.HasIndex(u => u.PhoneNumber).IsUnique();

			// 1 to 1 между AspNetUser & Client
			entity.HasOne(u => u.Client)
				.WithOne(c => c.User)
				.HasForeignKey<Client>(c => c.UserId);

			// 1 to 1 AspNetUser & Employer
			entity.HasOne(u => u.Employer)
				.WithOne(e => e.User)
				.HasForeignKey<Employer>(e => e.UserId);
		});



		base.OnModelCreating(builder);
	}
}