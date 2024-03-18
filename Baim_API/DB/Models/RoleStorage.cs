using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DB.Models;
public static class RoleStorage
{
	public static List<IdentityRole> Roles { get; private set; }

	static RoleStorage()
	{
		Roles = new List<IdentityRole>()
	{
		new IdentityRole("Admin"),
		new IdentityRole("Manager"),
		new IdentityRole("Employee"),
		new IdentityRole("User")
	};
	}
}