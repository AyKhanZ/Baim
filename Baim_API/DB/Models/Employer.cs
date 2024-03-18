using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DB.Models;

public class Employer
{
	public int Id { get; set; }

	public string UserId { get; set; }
	public AspNetUser User { get; set; }

	public string Position { get; set; }
	public int Experience { get; set; }
	public string? Certificates { get; set; } 
}