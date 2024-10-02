namespace BWBE.Bodies;

public class UserInit
{
    public string FirstName { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string Password { get; set; } = null!;
    
    public byte Perms { get; set; }
}