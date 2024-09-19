// ReSharper disable MoveLocalFunctionAfterJumpStatement

// IMPORTS

using System.Security.Cryptography;
using System.Text;
using BWBE.Bodies;
using BWBE.Data;
using BWBE.Models;
using Microsoft.EntityFrameworkCore;

// FUNCTIONS

string Sha256Hash(string value) =>
    string.Concat(SHA256.HashData(Encoding.UTF8.GetBytes(value)).Select(item => item.ToString("x2")));

async Task<bool> AuthSession(BakeryCtx db, Session session)
{
    if (DateTime.Now - session.CreationDate < TimeSpan.FromDays(3))
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

async void CookStepUpdate(BakeryCtx db, List<CookStep> stepList)
{
    foreach (var step in stepList)
    {
        db.CookStep.Add(new CookStep { Id = step.Id - 1, Description = step.Description, RecipeId = step.RecipeId });
        db.CookStep.Remove(step);
        await db.SaveChangesAsync();
    }
}

// API SETUP

var methodsOrder = new[] { "get", "post", "put", "patch", "delete", "options", "trace" };

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<BakeryCtx>();
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => c.OrderActionsBy(apiDesc =>
    $"{apiDesc.ActionDescriptor.RouteValues["controller"]}_{Array.IndexOf(methodsOrder, apiDesc.HttpMethod!.ToLower())}"));

var app = builder.Build();
app.UseSwagger();
app.UseSwaggerUI(options => options.DefaultModelsExpandDepth(-1));

// ENDPOINT MAPPINGS

// LOGIN ENDPOINTS

// RETRIEVES ALL USERS - RESTRICTED TO DEV USE ONLY
app.MapGet("users", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return Environment.GetEnvironmentVariable("DEV_AUTH_KEY") != token
        ? Results.StatusCode(403)
        : Results.Ok(await db.User.ToListAsync());
});

// RETRIEVES USER BY ID
app.MapGet("users/{id}", async (string id, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    // DEV SEARCH OVERRIDE
    if (token == Environment.GetEnvironmentVariable("DEV_AUTH_KEY"))
    {
        var usr = await db.User.FindAsync(id);

        return usr is not null ? Results.Ok(usr) : Results.NotFound();
    }

    // AUTHENTICATE REQUESTING USER AS SEARCHED USER
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    if (await db.User.FindAsync(session.UserId) is not { } user) return Results.StatusCode(500);

    // RETURN USER IF MATCHES REQUESTING USER'S ID
    return user.Id != id ? Results.StatusCode(403) : Results.Ok(user);
});

// RETRIEVES USER BY USERNAME
app.MapGet("users/search/uname/{uname}", async (string uname, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    // DEV SEARCH OVERRIDE
    if (token == Environment.GetEnvironmentVariable("DEV_AUTH_KEY"))
    {
        return await db.User.FirstOrDefaultAsync(x => x.Username == uname) is { } usr
            ? Results.Ok(usr)
            : Results.NotFound();
    }

    // AUTHENTICATE REQUESTING USER AS SEARCHED USER
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    if (await db.User.FindAsync(session.UserId) is not { } user) return Results.StatusCode(500);

    // RETURN USER IF MATCHES REQUESTING USER'S USERNAME
    return user.Username != uname ? Results.StatusCode(403) : Results.Ok(user);
});

// RETRIEVES ALL SESSIONS - RESTRICTED TO DEV USE ONLY
app.MapGet("session", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : Results.Ok(await db.Session.ToListAsync());
});

// RETRIEVES SESSION BY ID - RESTRICTED TO DEV USE ONLY
app.MapGet("session/{id}", async (string id, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : await db.Session.FindAsync(id) is { } session
            ? Results.Ok(session)
            : Results.NotFound();
});

// RETRIEVES SESSION BY USER ID - RESTRICTED TO DEV USE ONLY
app.MapGet("session/search/uid/{userId}", async (string userId, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : await db.Session.FirstOrDefaultAsync(x => x.UserId == userId) is { } session
            ? Results.Ok(session)
            : Results.NotFound();
});

// CREATES A USER AND RETURNS ASSOCIATED INITIAL SESSION
// NOTE: USER SHOULD NOT HAVE TO LOGIN AFTER REGISTERING AS LOGIN IS TO GENERATE A NEW SESSION
app.MapPost("register/user", async (UserInit init, BakeryCtx db) =>
{
    // CREATE USER FROM PASSED INIT BODY
    var user = new User
    {
        Id = Guid.NewGuid().ToString(),
        FirstName = init.FirstName,
        LastName = init.LastName,
        Username = init.Username,
        PassHash = Sha256Hash(init.Password + init.PassSalt),
        PassSalt = init.PassSalt
    };

    // ADD THE USER TO THE DATABASE
    db.Add(user);
    await db.SaveChangesAsync();

    // CREATE A NEW SESSION BASED ON THE NEWLY CREATED USER
    var session = new Session
    {
        Id = Guid.NewGuid().ToString(),
        UserId = user.Id,
        CreationDate = DateTime.Now,
        LastActiveDate = DateTime.Now
    };

    // ADD THE SESSION TO THE DATABASE
    db.Add(session);
    await db.SaveChangesAsync();

    // INDICATE SUCCESSFUL RESOURCE CREATION AND PASS BACK NEW SESSION OBJECT
    return Results.Created($"session/{session.Id}", session);
});

// CREATES AN EMAIL OBJECT ASSOCIATED WITH A USER
// NOTE: THIS SHOULD BE RUN ALONG SIDE INITIAL REGISTRATION AS A SEPARATE REQUEST FOLLOWING 
// USER CREATION, BASED ON INFORMATION GATHERED FROM REGISTRATION PAGE
app.MapPost("register/email", async (Email email, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    // AUTHENTICATE INDICATED SESSION PASSED BY AUTHORIZATION HEADER
    if (await GetSession(db, token) is not { } session) return Results.NotFound();
    if (session.UserId != email.UserId) return Results.StatusCode(403);

    // ADD EMAIL TO THE DATABASE
    db.Email.Add(email);
    await db.SaveChangesAsync();

    // INDICATE SUCCESSFUL RESOURCE CREATION AND PASS BACK NEW EMAIL OBJECT
    return Results.Created($"emails/{email.UserId}/{email.Id}", email);
});

// CREATES A PHONE OBJECT ASSOCIATED WITH A USER
// NOTE: THIS SHOULD BE RUN ALONGSIDE INITIAL REGISTRATION AS A SEPARATE REQUEST FOLLOWING
// USER CREATION, BASED ON INFORMATION 
app.MapPost("register/phone", async (PhoneNumber phone, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    // AUTHENTICATE INDICATED SESSION PASSED BY AUTHORIZATION HEADER
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    if (session.UserId != phone.UserId) return Results.StatusCode(403);

    // ADD PHONE NUMBER TO THE DATABASE
    db.PhoneNumber.Add(phone);
    await db.SaveChangesAsync();

    // INDICATE SUCCESSFUL RESOURCE CREATION AND PASS BACK NEW PHONE NUMBER OBJECT
    return Results.Created($"phone/{phone.UserId}/{phone.Number}", phone);
});

// CREATES A NEW SESSION - INVALIDATING PRE-EXISTING SESSIONS
app.MapPost("login", async (Login login, BakeryCtx db) =>
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

    return Results.Created($"session/{newSession.Id}", newSession);
});

app.MapPut("user/{id}", async (string id, UserInit init, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    if (session.UserId != id) return Results.StatusCode(403);
    if (await db.User.FindAsync(session.UserId) is not { } user) return Results.StatusCode(403);

    user.FirstName = init.FirstName;
    user.LastName = init.LastName;
    user.Username = init.Username;
    user.PassHash = Sha256Hash(init.Password + init.PassSalt);
    user.PassSalt = init.PassSalt;
    user.Perms = init.Perms;

    db.Update(user);
    await db.SaveChangesAsync();

    return Results.Ok();
});

app.MapPut("phone/{userId}/{phoneNum}",
    async (string userId, string phoneNum, PhoneNumber phone, HttpRequest request, BakeryCtx db) =>
    {
        var token = request.Headers.Authorization.ToString();

        if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
        if (session.UserId != userId) return Results.StatusCode(403);

        if (await db.PhoneNumber.FirstOrDefaultAsync(x => x.UserId == userId && x.Number == phoneNum) is null)
            return Results.NotFound();

        db.PhoneNumber.Update(phone);
        await db.SaveChangesAsync();

        return Results.Ok();
    });

app.MapPut("email/{userId}/{emailAddr}",
    async (string userId, string emailAddr, Email email, HttpRequest request, BakeryCtx db) =>
    {
        var token = request.Headers.Authorization.ToString();

        if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
        if (session.UserId != userId) return Results.StatusCode(403);

        if (await db.Email.FirstOrDefaultAsync(x => x.UserId == userId && x.EmailAddress == emailAddr) is null)
            return Results.NotFound();

        db.Email.Update(email);
        await db.SaveChangesAsync();

        return Results.Ok();
    });

app.MapDelete("user/{uname}", async (HttpRequest request, string uname, BakeryCtx db) =>
{
    if (await db.User.FirstOrDefaultAsync(x => x.Username == uname) is not { } user) return Results.NotFound();

    if (await db.Session.FirstOrDefaultAsync(x => x.UserId == user.Id) is not { } session)
        return Results.StatusCode(403);

    if (request.Headers.Authorization != session.Id ||
        request.Headers.Authorization != Environment.GetEnvironmentVariable("DEV_AUTH_KEY"))
        return Results.StatusCode(403);

    db.User.Remove(user);
    await db.SaveChangesAsync();

    return Results.Ok();
});

// INVENTORY ENDPOINTS

app.MapGet("inventory", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return await GetSession(db, token) is null ? Results.StatusCode(403) : Results.Ok(db.InventoryItem);
});

app.MapGet("inventory/id/{itemId}", async (HttpRequest request, string itemId, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (await GetSession(db, token) is null) return Results.StatusCode(403);
    //if (await.db.InventoryItem.FirstOrDefaultAsync(x => x.ItemID == itemID) is not { } item) return Results.NoContent();

    return await db.InventoryItem.FirstOrDefaultAsync(x => x.Id == itemId) is null
        ? Results.NoContent()
        : Results.Ok(await db.InventoryItem.FirstOrDefaultAsync(x => x.Id == itemId));
});

app.MapGet("inventory/name/{name}", async (HttpRequest request, string name, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (await GetSession(db, token) is null) return Results.StatusCode(403);

    return await db.InventoryItem.FirstOrDefaultAsync(x => x.Name == name) is null
        ? Results.NoContent()
        : Results.Ok(await db.InventoryItem.FirstOrDefaultAsync(x => x.Name == name));
});
// json input 
app.MapPost("inventory", async (HttpRequest request, InventoryItemInit init, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();
    if (await GetSession(db, token) is null) return Results.StatusCode(403);

    var inventoryItem = new InventoryItem
    {
        Id = Guid.NewGuid().ToString(),
        Name = init.Name,
        Quantity = init.Quantity,
        PurchaseQuantity = init.PurchaseQuantity,
        CostPerPurchaseUnit = init.CostPerPurchaseUnit,
        Unit = init.Unit,
        Notes = init.Notes
    };

    db.Add(inventoryItem);
    await db.SaveChangesAsync();

    return Results.Created(inventoryItem.Id, inventoryItem);
});

app.MapPut("inventory", async (HttpRequest request, InventoryItemInit init, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (await GetSession(db, token) is null) return Results.StatusCode(403);
    if (await db.InventoryItem.FirstOrDefaultAsync(x => x.Name == init.Name) is not { } item) return Results.NotFound();

    item.Name = init.Name != "" ? init.Name : item.Name;
    item.Quantity = init.Quantity;
    item.PurchaseQuantity = init.PurchaseQuantity;
    item.CostPerPurchaseUnit = init.CostPerPurchaseUnit;
    item.Unit = init.Unit != "" ? init.Unit : item.Unit;
    item.Notes = init.Notes != "" ? init.Notes : item.Notes;

    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapDelete("inventory/delete/name/{name}", async (HttpRequest request, string name, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (await GetSession(db, token) is null) return Results.StatusCode(403);

    if (await db.InventoryItem.FirstOrDefaultAsync(x => x.Name == name) is not { } inventoryItem)
        return Results.NotFound();

    db.InventoryItem.Remove(inventoryItem);
    await db.SaveChangesAsync();

    return Results.Ok();
});

app.MapDelete("inventory/delete/id/{id}", async (HttpRequest request, string id, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (await GetSession(db, token) is null) return Results.StatusCode(403);

    if (await db.InventoryItem.FirstOrDefaultAsync(x => x.Id == id) is not { } inventoryItem) return Results.NotFound();

    db.InventoryItem.Remove(inventoryItem);
    await db.SaveChangesAsync();

    return Results.Ok();
});

// RECIPE ENDPOINTS

app.MapGet("recipes", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();


    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : await db.Recipe.ToListAsync() is { } recipe
            ? Results.Ok(recipe)
            : Results.NotFound();
});

app.MapGet("recipes/id/{id}", async (string id, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : await db.Recipe.FindAsync(id) is { } recipe
            ? Results.Ok(recipe)
            : Results.NotFound();
});

app.MapGet("cookStep/recipeId/{recipeId}", async (string recipeId, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")) return Results.StatusCode(403);
    var list = await db.CookStep.Where(x => x.RecipeId == recipeId).ToListAsync();
    return Results.Ok(list);
});

app.MapPost("recipes", async (HttpRequest request, RecipeInit init, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();
    if (await GetSession(db, token) is null) return Results.StatusCode(403);

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

    return Results.Created($"recipes/{recipe.Id}", recipe);
});

app.MapPost("cookStep", async (CookStepInit init, BakeryCtx db) =>
{
    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == init.RecipeId) is null) return Results.NotFound();

    var count = await db.CookStep.Where(x => x.RecipeId == init.RecipeId)
        .CountAsync(); //unsure if count automatically returns a integer

    var cookStep = new CookStep
    {
        Id = count + 1,
        Description = init.Description,
        RecipeId = init.RecipeId
    };

    db.Add(cookStep);
    await db.SaveChangesAsync();

    return Results.Created($"cookStep/{cookStep.Id}", cookStep);
});

app.MapDelete("recipes/{id}", async (string id, BakeryCtx db) =>
{
    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == id) is not { } recipe) return Results.NotFound();

    db.Recipe.Remove(recipe);
    await db.SaveChangesAsync();

    return Results.Ok();
});


app.MapDelete("cookStep/id/{id:int}/recipeId/{recipeId}", async (int id, string recipeId, BakeryCtx db) =>
{
    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == recipeId) is null) return Results.NotFound();
    if (await db.CookStep.FirstOrDefaultAsync(z => z.Id == id) is not { } cookStep) return Results.NotFound();


    var stepList = await db.CookStep.Where(y => y.RecipeId == recipeId).Where(y => y.Id > cookStep.Id).ToListAsync();

    db.CookStep.Remove(cookStep);
    await db.SaveChangesAsync();

    CookStepUpdate(db, stepList);

    return Results.Ok();
});

// API EXECUTION

app.Run();