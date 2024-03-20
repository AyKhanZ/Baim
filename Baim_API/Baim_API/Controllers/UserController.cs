using DB.DbContexts;
using DB.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations.Schema;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace Baim_API.Controllers;

[ApiController]
[Route("User")]
public class UserController : ControllerBase
{
	// prover rabotaet li bez nix
	[NotMapped]
	public class UserModel
	{
		public string Email { get; set; }
		public string Password { get; set; }
	}

	[NotMapped]
	public class UserLoginModel : UserModel
	{
		public bool RememberMe { get; set; } = true;
	}

	private readonly BaimContext _dbContext;
	private readonly UserManager<AspNetUser> _userManager;
	private readonly SignInManager<AspNetUser> _signInManager;
	private readonly IUserStore<AspNetUser> _userStore;
	private readonly IConfiguration _configuration;
	private readonly IEmailSender _emailSender;

	// role manager add 
	public UserController(BaimContext dbContext,
		UserManager<AspNetUser> userManager,
		IUserStore<AspNetUser> userStore,
		SignInManager<AspNetUser> signInManager,
		IConfiguration configuration,
		IEmailSender emailSender)
	{
		_dbContext = dbContext;
		_userManager = userManager;
		_userStore = userStore;
		_signInManager = signInManager;
		_configuration = configuration;
		_emailSender = emailSender;
	}


	[HttpPost("Login")]
	public async Task<IActionResult> Login([FromBody] UserLoginModel model)
	{
		if (ModelState.IsValid)
		{
			var user = await _userManager.FindByEmailAsync(model.Email);
			if (user != null)
			{
				var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);
				if (result.Succeeded)
				{
					var tokenString = GenerateTokenString(user);
					return Ok(new { UserId = user.Id, Token = tokenString });
				}
				return BadRequest("Invalid login attempt");
			}
		}
		return BadRequest("Not valid attempt");

	}

	[HttpPost("Registration")]
	public async Task<IActionResult> Registration([FromBody] UserModel model)
	{
		if (!ModelState.IsValid) return BadRequest("Invalid model state");

		IActionResult emailCheckResult = CheckEmail(model.Email);
		if (emailCheckResult is BadRequestObjectResult) return emailCheckResult;

		IActionResult passwordCheckResult = CheckPassword(model.Password);
		if (passwordCheckResult is BadRequestObjectResult) return passwordCheckResult;

		if (await _dbContext.Users.AnyAsync(a => a.Email == model.Email)) return BadRequest("User already exists");

		var newUser = new AspNetUser
		{
			Email = model.Email,
			NormalizedEmail = model.Email.ToUpper()
		};

		await _userStore.SetUserNameAsync(newUser, model.Email, CancellationToken.None);
		await _userManager.GetUserIdAsync(newUser);

		var result = await _userManager.CreateAsync(newUser, model.Password);

		if (result.Succeeded)
		{
			// Отправьте подтверждение по электронной почте
			var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
			var confirmationLink = Url.Action("ConfirmEmail", "Account", new { userId = newUser.Id, token = token }, Request.Scheme);
			await _emailSender.SendEmailAsync(newUser.Email, "Подтверждение регистрации", $"Пожалуйста, подтвердите свою регистрацию, перейдя по ссылке: {confirmationLink}");

			var tokenString = GenerateTokenString(newUser);
			// adding roles
			await _dbContext.SaveChangesAsync();

			return Ok(new { UserId = newUser.Id, Token = tokenString });
		}

		return BadRequest("Registration failed");
	}

	[HttpGet("CheckEmail")]
	public IActionResult CheckEmail(string email)
	{
		if (Regex.IsMatch(email, "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$"))
		{
			return Ok();
		}
		return BadRequest("Invalid email format");
	}


	[HttpGet("CheckPassword")]
	public IActionResult CheckPassword(string password)
	{
		if (Regex.IsMatch(password, "^(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=-_'.!]).{6,40}$"))
		{
			return Ok();
		}
		return BadRequest("Password must be more than 6 and less than 40 characters long and special symbol");
	}


	private string GenerateTokenString(AspNetUser user)
	{
		var claims = new List<Claim>
			{
				new Claim(ClaimTypes.Email,user.UserName),
				new Claim(ClaimTypes.NameIdentifier,user.Id),
				new Claim(ClaimTypes.Role,"User"),
			};

		var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

		var signingCred = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

		var securityToken = new JwtSecurityToken(
			claims: claims,
			expires: DateTime.Now.AddMinutes(60),
			issuer: _configuration["Jwt:Issuer"],
			audience: _configuration["Jwt:Audience"],
			signingCredentials: signingCred);

		string tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);
		return tokenString;
	}
}
