using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DB.Models;

public class Client
{
	public int Id { get; set; }

	public string UserId { get; set; }
    public AspNetUser User { get; set; }

	public bool IsPublic { get; set; } // Для приватности 
	public byte[]? ClientFeedback { get; set; } // image
	public byte[]? ClientConfirm { get; set; } // image
	public string? YoutubeLink { get; set; }

	public List<Product>? Products { get; set; }
}