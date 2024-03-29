﻿namespace DB.Models;
public enum PrivacyLevel
{
	Public,
	Private,
	Secret
}
public class Project
{
    public int Id { get; set; }
    public string Name { get; set; } 
    public string? Description { get; set; }
	public byte[]? DesignTheme { get; set; }
	// Del '?'
	public byte[]? Avatar { get; set; }
	// Del '?'
	public PrivacyLevel? PrivacyLevel { get; set; }
	// TeamMembers
	// Admins 
	// Tasks
}