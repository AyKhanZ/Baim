namespace DB.Models; 

public enum DoneState
{
	Pending,   // Ожидающий подтверждения,
	InProcess, // В процессе,
	Done,      // Сделано, 
	Cancelled  // Отмененный
}
public enum PaymentMethod
{
	Cash,   
	Online  
}

public class Order
{
	public int Id { get; set; }
	public DateTime? StartDate { get; set; }
	public DateTime? DoneDate { get; set; }
	public decimal TotalPrice { get; set; }
	public PaymentMethod? PaymentMethod { get; set; }

	public string? UserId { get; set; }
	public AspNetUser? User { get; set; }

	public List<OrderProduct> OrderProducts { get; set; }
}