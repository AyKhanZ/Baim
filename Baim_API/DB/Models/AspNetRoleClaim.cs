using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DB.Models;
[Table("AspNetRoleClaims")]
[NotMapped]

public partial class AspNetRoleClaim : IdentityRoleClaim<string>
{ 
	public virtual AspNetRole Role { get; set; } = null!;
}
