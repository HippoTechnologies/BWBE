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

app.MapGet("/recipes", async (HttpRequest request, BakeryCtx db) => { 
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : await db.Recipe.ToListAsync() is { } recipe
            ? Results.Ok(recipe)
            : Results.NotFound();
});

app.MapGet("/recipes/id/{id}", async (int id, HttpRequest request, BakeryCtx db) => {
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : await db.Recipe.FindAsync(id) is { } recipe
            ? Results.Ok(recipe)
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

app.MapPost("/recipes", async (RecipeInit init, BakeryCtx db) =>
{
    var recipe = new Recipe
    {
        Id = Guid.NewGuid().ToString(),
        Name = init.Name,
        Description = init.Description,
        PrepUnit = init.PrepUnit,
        CookUnit = init.CookUnit,
        Rating = init.Rating,
        PrepTime = init.PrepTime,
        CookTime = init.CookTime
    };

    db.Add(recipe);
    await db.SaveChangesAsync();

    return Results.Created($"/recipes/{recipe.Id}", recipe);
});

app.MapPost("/cookstep/id:{id}", async (CookStepInit init, BakeryCtx db) =>
{
    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == init.RecipeId) is not { } recipe) return Results.NotFound();

    int count = await db.CookStep.Where(x => x.RecipeId == init.RecipeId).CountAsync(); //unsure if count automatically returns a integer

    var cookStep = new CookStep
    {
        Id = count + 1,
        Description = init.Description,
        RecipeId = init.RecipeId
    }; 

    db.Add(cookStep);
    await db.SaveChangesAsync();

    return Results.Created($"/cookstep/{cookStep.Id}", cookStep);
});

app.MapDelete("/user/{uname}", async (string uname, BakeryCtx db) =>
{
    if (await db.User.FirstOrDefaultAsync(x => x.Username == uname) is not { } user) return Results.NotFound();

    db.User.Remove(user);
    await db.SaveChangesAsync();

    return Results.Ok();
});

app.MapDelete("/recipes/{id}", async (string id, BakeryCtx db) =>
{
    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == id) is not { } recipe) return Results.NotFound();

    db.Recipe.Remove(recipe);
    await db.SaveChangesAsync();

    return Results.Ok();
});

app.MapDelete("/cookstep/", async (CookStepDelete deleteInfo, BakeryCtx db) =>
{
    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == deleteInfo.RecipeId) is not { } recipe) return Results.NotFound();
    if (await db.CookStep.FirstOrDefaultAsync(x => x.Id == deleteInfo.Id) is not { } cookStep) return Results.NotFound();

    db.CookStep.Remove(cookStep);
    await db.SaveChangesAsync();

    return Results.Ok();
});


app.Run();