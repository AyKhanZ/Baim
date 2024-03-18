using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DB.Models;
 
public class Task
{
	public int Id { get; set; }
	public string Title { get; set; }
	public bool? IsVeryImportant { get; set; }
	public string? Description { get; set; }
	// Del '?'
	public DateTime? StartDate { get; set; }
	// Del '?'
	public DateTime? DeadLine { get; set; }

	// Del '?'
	public string? ExecutorId { get; set; }
	public AspNetUser? Executor { get; set; }

	// Del '?'
	public string? CoExecutorId { get; set; }
	public AspNetUser? CoExecutor { get; set; }

	// Del '?'
	public string? ObserverId { get; set; }
	public AspNetUser? Observer { get; set; }
}