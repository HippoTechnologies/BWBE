using System.Security.Cryptography;
using System.Text;
using BWBE.Bodies;
using BWBE.Data;
using BWBE.Models;
using Microsoft.EntityFrameworkCore;

string Sha256Hash(string value) =>
    string.Concat(SHA256.HashData(Encoding.UTF8.GetBytes(value)).Select(item => item.ToString("x2")));

async Task<bool> AuthSession(BakeryCtx db, Session session)
{
    if (DateTime.Now - session.CreationDate <= TimeSpan.FromDays(3))
    {
        session.LastActiveDate = DateTime.Now;
        db.Session.Update(session);
        await db.SaveChangesAsync();

        return true;
    }

    db.Session.Remove(session);
    await db.SaveChangesAsync();

    return false;
}

async Task<Session?> GetSession(BakeryCtx db, string token)
{
    if (await db.Session.FindAsync(token) is not { } session) return null;

    if (!await AuthSession(db, session)) return null;

    return session;
}

string[] methodsOrder = new string[7] { "get", "post", "put", "patch", "delete", "options", "trace" };

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<BakeryCtx>();
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => c.OrderActionsBy(apiDesc =>
    $"{apiDesc.ActionDescriptor.RouteValues["controller"]}_{Array.IndexOf(methodsOrder, apiDesc.HttpMethod!.ToLower())}"));

var app = builder.Build();
app.UseSwagger();
app.UseSwaggerUI(options => options.DefaultModelsExpandDepth(-1));

app.MapGet("/users", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return Environment.GetEnvironmentVariable("DEV_AUTH_KEY") != token
        ? Results.StatusCode(403)
        : Results.Ok(await db.User.ToListAsync());
});

app.MapGet("/users/search/uname/{uname}", async (string uname, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token == Environment.GetEnvironmentVariable("DEV_AUTH_KEY"))
    {
        return await db.User.FirstOrDefaultAsync(x => x.Username == uname) is { } usr
            ? Results.Ok(usr)
            : Results.NotFound();
    }

    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);

    if (await db.User.FindAsync(session.UserId) is not { } user) return Results.StatusCode(500);

    return user.Username != uname ? Results.StatusCode(403) : Results.Ok(user);
});

app.MapGet("/users/search/id/{id}", async (string id, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token == Environment.GetEnvironmentVariable("DEV_AUTH_KEY"))
    {
        var usr = await db.User.FindAsync(id);

        return usr is not null ? Results.Ok(usr) : Results.NotFound();
    }

    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);

    if (await db.User.FindAsync(session.UserId) is not { } user) return Results.StatusCode(500);

    return user.Id != id ? Results.StatusCode(403) : Results.Ok(user);
});

app.MapGet("/session", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : Results.Ok(await db.Session.ToListAsync());
});

app.MapGet("/session/search/uid/{userId}", async (string userId, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : await db.Session.FirstOrDefaultAsync(x => x.UserId == userId) is { } session
            ? Results.Ok(session)
            : Results.NotFound();
});

app.MapGet("/session/search/id/{id}", async (string id, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : await db.Session.FindAsync(id) is { } session
            ? Results.Ok(session)
            : Results.NotFound();
});

app.MapPost("/users", async (UserInit init, BakeryCtx db) =>
{
    var user = new User
    {
        Id = Guid.NewGuid().ToString(),
        FirstName = init.FirstName,
        LastName = init.LastName,
        Username = init.Username,
        PassHash = Sha256Hash(init.Password + init.PassSalt),
        PassSalt = init.PassSalt
    };

    db.Add(user);
    await db.SaveChangesAsync();

    var session = new Session()
    {
        Id = Guid.NewGuid().ToString(),
        UserId = user.Id,
        CreationDate = DateTime.Now,
        LastActiveDate = DateTime.Now
    };

    db.Add(session);
    await db.SaveChangesAsync();

    return Results.Created($"/sessions/{session.Id}", session);
});

app.MapPost("/login", async (Login login, BakeryCtx db) =>
{
    if (await db.User.FirstOrDefaultAsync(x => x.Username == login.Username) is not { } user) return Results.NotFound();

    if (Sha256Hash(login.Password + user.PassSalt) != user.PassHash) return Results.NotFound();

    if (await db.Session.FirstOrDefaultAsync(x => x.UserId == user.Id) is { } session)
    {
        db.Session.Remove(session);
        await db.SaveChangesAsync();
    }

    var newSession = new Session
    {
        Id = Guid.NewGuid().ToString(),
        UserId = user.Id,
        CreationDate = DateTime.Now,
        LastActiveDate = DateTime.Now
    };

    db.Session.Add(newSession);
    await db.SaveChangesAsync();

    return Results.Created($"/sessions/{newSession.Id}", newSession);
});

app.MapPost("/email", async () => Results.Ok());

app.MapDelete("/user/{uname}", async (string uname, BakeryCtx db) =>
{
    if (await db.User.FirstOrDefaultAsync(x => x.Username == uname) is not { } user) return Results.NotFound();

    db.User.Remove(user);
    await db.SaveChangesAsync();

    return Results.Ok();
});

app.MapGet("/inventory", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    return Results.Ok(db.InventoryItem);           
});

app.MapGet("/inventory/{itemID}", async (HttpRequest request, string itemID, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    //if (await.db.InventoryItem.FirstOrDefaultAsync(x => x.ItemID == itemID) is not { } item) return Results.NoContent();
    
    return await db.InventoryItem.FirstOrDefaultAsync(x => x.ID == itemID) is not { } item 
        ? Results.NoContent() 
        : Results.Ok(await db.InventoryItem.FirstOrDefaultAsync(x => x.ID == itemID));
    //db.Database.SqlQuery<string>("SELECT * FROM Bakery.InventoryItem WHERE ItemID = @itemID").ToList();

});

app.MapGet("/inventory/{name}", async (HttpRequest request, string name, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    
    return await db.InventoryItem.FirstOrDefaultAsync(x => x.Name == name) is not { } item
        ? Results.NoContent()
        : Results.Ok(await db.InventoryItem.FirstOrDefaultAsync(x => x.Name == name));
});
// json input 
app.MapPost("/inventory/{inputs}", async (HttpRequest request, InventoryItemInit init, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    
    var inventoryItem = new InventoryItem
    {
        ID = Guid.NewGuid().ToString(),
        Name = init.Name,
        Quantity = init.Quantity,
        PurchaseQuantity = init.PurchaseQuantity,
        CostPerPurchaseUnit = init.CostPerPurchaseUnit,
        Unit = init.Unit,
        Notes = init.Notes
    };

    db.Add(inventoryItem);
    await db.SaveChangesAsync();
    
    return Results.Created(inventoryItem.ID, inventoryItem);

});

app.MapPut("/inventory/{inputs}", async (HttpRequest request, InventoryItemInit init, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    
    var item =  await db.InventoryItem.FirstOrDefaultAsync(x => x.Name == init.Name);
    item.Name = (init.Name != null ? init.Name : item.Name);
    item.Quantity = (init.Quantity != null ? item.Quantity : init.Quantity);
    item.PurchaseQuantity = (init.PurchaseQuantity != null ? item.PurchaseQuantity : init.PurchaseQuantity);
    item.CostPerPurchaseUnit = (init.CostPerPurchaseUnit != null ? item.CostPerPurchaseUnit : init.CostPerPurchaseUnit);
    item.Unit = (init.Unit != null ? init.Unit : item.Unit);
    item.Notes = (init.Notes != null ? init.Notes : item.Notes);

    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapDelete("/inventory/delete/{name}", async (HttpRequest request, string name, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    
    if (await db.InventoryItem.FirstOrDefaultAsync(x => x.Name == name) is not { } inventoryItem) return Results.NotFound();

    db.InventoryItem.Remove(inventoryItem);
    await db.SaveChangesAsync();

    return Results.Ok();
});

app.Run();