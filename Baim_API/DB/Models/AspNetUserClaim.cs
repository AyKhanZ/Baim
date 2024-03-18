using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DB.Models;

[Table("AspNetUserClaims")]
[NotMapped]

public partial class AspNetUserClaim : IdentityUserClaim<string>
{
	public virtual AspNetUser User { get; set; } = null!;
}
