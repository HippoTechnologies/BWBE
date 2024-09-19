using BWBE.Models;
using Microsoft.EntityFrameworkCore;
using MySqlConnector;

namespace BWBE.Data;

public class BakeryCtx : DbContext
{
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        var server = Environment.GetEnvironmentVariable("SERVER_IP");
        var name = Environment.GetEnvironmentVariable("DB_NAME");
        var user = Environment.GetEnvironmentVariable("USERNAME");
        var pass = Environment.GetEnvironmentVariable("PASSWORD");

        var connection = $"server={server}; database={name}; user={user}; password={pass}";
        optionsBuilder.UseMySql(connection, ServerVersion.AutoDetect(connection));
    }
    
    public DbSet<User> User => Set<User>();

    public DbSet<Session> Session => Set<Session>();
    
    public DbSet<Email> Email => Set<Email>();
    
    public DbSet<PhoneNumber> PhoneNumber => Set<PhoneNumber>();
    
    public DbSet<InventoryItem> InventoryItem => Set<InventoryItem>();
}