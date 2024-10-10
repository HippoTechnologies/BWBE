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

async Task CookStepUpdate(BakeryCtx db, List<CookStep> stepList)
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
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        policyBuilder =>
        {
            policyBuilder.AllowAnyOrigin()
                   .AllowAnyMethod()
                   .AllowAnyHeader();
        });
});

var app = builder.Build();
app.UseSwagger();
app.UseSwaggerUI(options => options.DefaultModelsExpandDepth(-1));
app.UseCors("AllowAll");


// ENDPOINT MAPPINGS

// LOGIN ENDPOINTS

// RETRIEVES ALL USERS - RESTRICTED TO DEV USE ONLY
app.MapGet("/api/users", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return Environment.GetEnvironmentVariable("DEV_AUTH_KEY") != token
        ? Results.StatusCode(403)
        : Results.Ok(await db.User.ToListAsync());
});

        // RETRIEVES USER BY ID
app.MapGet("/api/users/{id}", async (string id, HttpRequest request, BakeryCtx db) =>
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
app.MapGet("/api/users/search/uname/{uname}", async (string uname, HttpRequest request, BakeryCtx db) =>

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
app.MapGet("/api/session", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : Results.Ok(await db.Session.ToListAsync());
});

        // RETRIEVES SESSION BY ID - RESTRICTED TO DEV USE ONLY
app.MapGet("/api/session/{id}", async (string id, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY")
        ? Results.StatusCode(403)
        : await db.Session.FindAsync(id) is { } session
            ? Results.Ok(session)
            : Results.NotFound();
});

        // RETRIEVES SESSION BY USER ID - RESTRICTED TO DEV USE ONLY
app.MapGet("/api/session/search/uid/{userId}", async (string userId, HttpRequest request, BakeryCtx db) =>
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
app.MapPost("/api/register/user", async (UserInit init, BakeryCtx db) =>
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
app.MapPost("/api/register/email", async (EmailInit email, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    // AUTHENTICATE INDICATED SESSION PASSED BY AUTHORIZATION HEADER
    if (await GetSession(db, token) is not { } session) return Results.NotFound();
    if (session.UserId != email.UserId) return Results.StatusCode(403);

    var newEmail = new Email()
    {
        Id = Guid.NewGuid().ToString(),
        EmailAddress = email.EmailAddress,
        UserId = email.UserId,
        Verified = false
    };
    
    // ADD EMAIL TO THE DATABASE
    db.Email.Add(newEmail);
    await db.SaveChangesAsync();

    // INDICATE SUCCESSFUL RESOURCE CREATION AND PASS BACK NEW EMAIL OBJECT
    return Results.Created($"emails/{email.UserId}/{newEmail.Id}", email);
});

        // CREATES A PHONE OBJECT ASSOCIATED WITH A USER
        // NOTE: THIS SHOULD BE RUN ALONGSIDE INITIAL REGISTRATION AS A SEPARATE REQUEST FOLLOWING
        // USER CREATION, BASED ON INFORMATION 
app.MapPost("/api/register/phone", async (PhoneInit phone, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    // AUTHENTICATE INDICATED SESSION PASSED BY AUTHORIZATION HEADER
    if (await GetSession(db, token) is not { } session) return Results.StatusCode(403);
    if (session.UserId != phone.UserId) return Results.StatusCode(403);
    
    var phoneNumber = new PhoneNumber()
    {
        Id = Guid.NewGuid().ToString(),
        CountryCode = phone.CountryCode,
        Number = phone.Number,
        UserId = phone.UserId,
        Verified = false
    };

    // ADD PHONE NUMBER TO THE DATABASE
    db.PhoneNumber.Add(phoneNumber);
    await db.SaveChangesAsync();

    // INDICATE SUCCESSFUL RESOURCE CREATION AND PASS BACK NEW PHONE NUMBER OBJECT
    return Results.Created($"phone/{phone.UserId}/{phone.Number}", phone);
});

        // CREATES A NEW SESSION - INVALIDATING PRE-EXISTING SESSIONS
app.MapPost("/api/login", async (Login login, BakeryCtx db) =>
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

app.MapPut("/api/user/{id}", async (string id, UserInit init, HttpRequest request, BakeryCtx db) =>
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

app.MapPut("/api/phone/{userId}/{phoneNum}",
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

app.MapPut("/api/email/{userId}/{emailAddr}",
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

app.MapDelete("/api/user/{uname}", async (HttpRequest request, string uname, BakeryCtx db) =>
{
    if (await db.User.FirstOrDefaultAsync(x => x.Username == uname) is not { } user) return Results.NotFound();

    if (request.Headers.Authorization == Environment.GetEnvironmentVariable("DEV_AUTH_KEY"))
    {
        db.User.Remove(user);
        await db.SaveChangesAsync();

        return Results.Ok();
    }
    
    if (await db.Session.FirstOrDefaultAsync(x => x.UserId == user.Id) is not { } session)
        return Results.StatusCode(403);

    if (request.Headers.Authorization != session.Id)
        return Results.StatusCode(403);

    db.User.Remove(user);
    await db.SaveChangesAsync();

    return Results.Ok();
});

// INVENTORY ENDPOINTS

app.MapGet("/api/inventory", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var inventoryList = await db.InventoryItem.ToListAsync();
    return Results.Ok(inventoryList);
});

app.MapGet("/api/ingredients", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null) 
    {
        return Results.StatusCode(403);
    }

    var ingredientsList = await db.Ingredient.ToListAsync();
    return Results.Ok(ingredientsList);
});

app.MapGet("/api/inventory/id/{itemId}", async (HttpRequest request, string itemId, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
        ? Results.StatusCode(403)
        : await db.InventoryItem.FindAsync(itemId) is { } item
            ? Results.Ok(item)
            : Results.NotFound();
});


app.MapGet("/api/inventory/name/{name}", async (HttpRequest request, string name, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
        ? Results.StatusCode(403)
        : await db.InventoryItem.FirstOrDefaultAsync(x=> x.Name == name) is { } item
            ? Results.Ok(item)
            : Results.NotFound();
});

/*
 * Not Supported
app.MapGet("/api/ingredients/id/{ingredientId}", async (HttpRequest request, int ingredientId, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is not { } session)
        ? Results.StatusCode(403)
        : await db.Ingredient.FindAsync(ingredientId) is { } ingredient
            ? Results.Ok(ingredient)
            : Results.NotFound();
});
*/ 

app.MapGet("/api/ingredients/recipeid/{recipeId}", async (HttpRequest request, string recipeId, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var ingredientsList = await db.Ingredient.Where(e => e.RecipeId == recipeId).ToListAsync();
    return Results.Ok(ingredientsList);
});

app.MapGet("/api/ingredients/recipeid/{recipeId}/id/{ingredientsId}", async (HttpRequest request, string recipeId, int ingredientsId, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    return (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
        ? Results.StatusCode(403)
        : await db.Ingredient.FindAsync(ingredientsId, recipeId) is { } ingredient
            ? Results.Ok(ingredient)
            : Results.NotFound();
});

app.MapGet("/api/ingredients/inventoryId/{inventoryId}/id/{ingredientId}", async (HttpRequest request, string inventoryId, int ingredientId, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var ingredientsList = await db.Ingredient.Where(e => e.InventoryId == inventoryId).Where(e => e.Id == ingredientId).ToListAsync();
    return Results.Ok(ingredientsList);
});
// json input 
app.MapPost("/api/inventory", async (HttpRequest request, InventoryItemInit init, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.InventoryItem.FindAsync(init.Name) is not null) {
        Results.BadRequest(500);
    }


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

    return Results.Created($"/api/inventory/{inventoryItem.Id}", inventoryItem);
});

app.MapPost("/api/ingredients", async (HttpRequest request, IngredientInit init, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.Ingredient.FirstOrDefaultAsync(x => x.InventoryId == init.InventoryId && x.RecipeId == init.RecipeId) is not null) return Results.BadRequest("Ingredient for recipe and inventory already exist");
    if (await db.InventoryItem.FindAsync(init.InventoryId) is not { } item) return Results.BadRequest("Inventory item does not exist");
    if (await db.Recipe.FindAsync(init.RecipeId) is null) return Results.BadRequest("Recipe does not exist");


    int count = await db.Ingredient.CountAsync();

    var ingredient = new Ingredient
    {
        Id = count + 1,
        RecipeId = init.RecipeId,
        InventoryId = init.InventoryId,
        Name = item.Name,
        Quantity = init.Quantity,
        MinQuantity = init.MinQuantity,
        Unit = init.Unit
    };

    db.Add(ingredient);
    await db.SaveChangesAsync();

    return Results.Created($"/api/inventory/{ingredient.Id}", ingredient);
});

app.MapPut("/api/inventory", async (HttpRequest request, InventoryItem update, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }
    if (await db.InventoryItem.FirstOrDefaultAsync(x => x.Id == update.Id) is not { } item) return Results.NotFound();

    item.Name = update.Name != "" ? update.Name : item.Name;
    item.Quantity = update.Quantity;
    item.PurchaseQuantity = update.PurchaseQuantity;
    item.CostPerPurchaseUnit = update.CostPerPurchaseUnit;
    item.Unit = update.Unit != "" ? update.Unit : item.Unit;
    item.Notes = update.Notes != "" ? update.Notes : item.Notes;

    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapPut("/api/ingredients", async (HttpRequest request, Ingredient update, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }
    if (await db.Ingredient.FirstOrDefaultAsync(x => x.Id == update.Id) is not { } ingredient) return Results.NotFound();

    ingredient.Unit = update.Unit != "" ? update.Unit : ingredient.Unit;

    //if init.rating and recipe.rating are the same, (0 = 0), we go with init.Rating.
    //This is in case init.Rating is 0 but recipe.Rating is also 0
    ingredient.Quantity = Math.Abs(ingredient.Quantity - update.Quantity) < 0.001 ? ingredient.Quantity : update.Quantity;
    ingredient.MinQuantity = Math.Abs(ingredient.MinQuantity - update.MinQuantity) < 0.001 ? ingredient.MinQuantity : update.MinQuantity;

    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapDelete("/api/inventory/name/{name}", async (HttpRequest request, string name, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.InventoryItem.FirstOrDefaultAsync(x => x.Name == name) is not { } inventoryItem) return Results.NotFound();

    db.InventoryItem.Remove(inventoryItem);
    await db.SaveChangesAsync();

    return Results.Ok();
});

app.MapDelete("/api/inventory/id/{id}", async (HttpRequest request, string id, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.InventoryItem.FirstOrDefaultAsync(x => x.Id == id) is not { } inventoryItem) return Results.NotFound();

    db.InventoryItem.Remove(inventoryItem);
    await db.SaveChangesAsync();

    return Results.Ok();
});

app.MapDelete("/api/ingredients/id/{id:int}", async (HttpRequest request, int id, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.Ingredient.FirstOrDefaultAsync(x => x.Id == id) is not { } ingredient) return Results.NotFound();

    db.Ingredient.Remove(ingredient);
    await db.SaveChangesAsync();

    return Results.Ok();
});



// RECIPE ENDPOINTS
app.MapGet("/api/recipes", async (HttpRequest request, BakeryCtx db) => {
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var recipeList = await db.Recipe.ToListAsync();
    return Results.Ok(recipeList);
});

app.MapGet("/api/recipes/id/{id}", async (string id, HttpRequest request, BakeryCtx db) => {
    var token = request.Headers.Authorization.ToString();

    return (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
        ? Results.StatusCode(403)
        : await db.Recipe.FindAsync(id) is { } recipe
            ? Results.Ok(recipe)
            : Results.NotFound();
});

app.MapGet("/api/cookstep/recipeid/{recipeId}", async (string recipeId, HttpRequest request, BakeryCtx db) => {
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var list = await db.CookStep.Where(x => x.RecipeId == recipeId).ToListAsync();
    return Results.Ok(list);
});

app.MapGet("/api/cookstep/recipeid/{recipeId}/id/{id}", async (string recipeId, int id, HttpRequest request, BakeryCtx db) => {
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var list = await db.CookStep.FindAsync(id, recipeId);
    return Results.Ok(list);
});

app.MapPost("/api/recipes", async (RecipeInit init, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

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

    return Results.Created($"/api/recipes/{recipe.Id}", recipe);
});

app.MapPost("/api/cookstep", async (CookStepInit init, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == init.RecipeId) is null) return Results.NotFound();

    int count = await db.CookStep.Where(x => x.RecipeId == init.RecipeId).CountAsync(); //unsure if count automatically returns a integer

    var cookStep = new CookStep
    {
        Id = count + 1,
        Description = init.Description,
        RecipeId = init.RecipeId
    };

    db.Add(cookStep);
    await db.SaveChangesAsync();

    return Results.Created($"/api/cookstep/{cookStep.Id}", cookStep);
});

app.MapPut("/api/recipes", async (HttpRequest request, Recipe update, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }
    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == update.Id) is not { } recipe) return Results.NotFound();

    recipe.Name = update.Name != "" ? update.Name : recipe.Name;
    recipe.Description = update.Description != "" ? update.Description : recipe.Description;
    recipe.PrepUnit = update.PrepUnit != "" ? update.PrepUnit : recipe.PrepUnit;
    recipe.CookUnit = update.CookUnit != "" ? update.CookUnit : recipe.CookUnit;

    recipe.Rating = update.Rating;
    recipe.PrepTime = Math.Abs(update.PrepTime - recipe.PrepTime) < 0.0001 ? recipe.PrepTime : update.PrepTime;
    recipe.CookTime = Math.Abs(update.CookTime - recipe.CookTime) < 0.0001 ? recipe.CookTime : update.CookTime;

    if ( (await db.CookedGood.FindAsync(recipe.Id) is { } good) && (good.Name != recipe.Name) ) good.Name = recipe.Name;

    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapPut("/api/cookstep", async (HttpRequest request, CookStep update, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }
    if (await db.CookStep.FindAsync(update.Id, update.RecipeId) is not { } cookStep) return Results.NotFound();

    cookStep.Description = update.Description;


    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapDelete("/api/recipes", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var recipeList = await db.Recipe.ToListAsync();
    foreach (var recipe in recipeList)
    {
        db.Recipe.Remove(recipe);
        await db.SaveChangesAsync();
    }

    return Results.Ok();
});

app.MapDelete("/api/recipes/{id}", async (string id, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == id) is not { } recipe) return Results.NotFound();

    db.Recipe.Remove(recipe);
    await db.SaveChangesAsync();

    return Results.Ok();
});

app.MapDelete("/api/cookstep/id/{id}/recipeid/{recipeId}", async (int id, string recipeId, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == recipeId) is null) return Results.NotFound();
    if (await db.CookStep.FirstOrDefaultAsync(z => z.Id == id) is not { } cookStep) return Results.NotFound();


    var stepList = await db.CookStep.Where(y => (y.RecipeId == recipeId)).Where(y => y.Id > cookStep.Id).ToListAsync();

    db.CookStep.Remove(cookStep);
    await db.SaveChangesAsync();

    await CookStepUpdate(db, stepList);

    return Results.Ok();
});

// COOKED GOOD API
app.MapGet("/api/cookedgoods", async (HttpRequest request, BakeryCtx db) => {
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var cookedList = await db.CookedGood.ToListAsync();
    return Results.Ok(cookedList);
});

app.MapGet("/api/cookedgoods/recipeid/{recipeid}", async (string recipeid, HttpRequest request, BakeryCtx db) => {
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var cookedList = await db.CookedGood.FindAsync(recipeid);
    return Results.Ok(cookedList);
});

app.MapPost("/api/cookedgoods", async (CookedGoodInit init, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.Recipe.FirstOrDefaultAsync(x => x.Id == init.RecipeId) is not { } recipe) return Results.NotFound();

    if (await db.CookedGood.FirstOrDefaultAsync(x => x.RecipeId == init.RecipeId) is not null) return Results.BadRequest("Good already exists");

    var cookedGood = new CookedGood
    {
        Id = Guid.NewGuid().ToString(),
        Name = recipe.Name,
        RecipeId = recipe.Id,
        Quantity = init.Quantity
    };

    db.Add(cookedGood);
    await db.SaveChangesAsync();

    return Results.Created($"/api/cookedgoods/{cookedGood.Id}", cookedGood);
});

app.MapPut("/api/cookedgoods", async (HttpRequest request, CookedGoodInit update, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }
    if (await db.CookedGood.FirstOrDefaultAsync(x => x.RecipeId == update.RecipeId) is not { } good) return Results.NotFound();

    good.Quantity = update.Quantity;

    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapPut("/api/cookedgoods/{name}/consume/{count}", async (HttpRequest request, string name, int count, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }
    if (await db.CookedGood.FirstOrDefaultAsync(x => x.Name == name) is not { } good) return Results.NotFound();

    good.Quantity = good.Quantity - count;

    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapPut("/api/cookedgoods/{name}/add/{count}", async (HttpRequest request, string name, int count, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }
    if (await db.CookedGood.FirstOrDefaultAsync(x => x.Name == name) is not { } good) return Results.NotFound();

    good.Quantity = good.Quantity + count;

    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapDelete("/api/cookedgoods", async (HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    var goodsList = await db.CookedGood.ToListAsync();
    foreach (var good in goodsList)
    {
        db.CookedGood.Remove(good);
        await db.SaveChangesAsync();
    }

    return Results.Ok();
});

app.MapDelete("/api/cookedgoods/recipeid/{id}", async (string id, HttpRequest request, BakeryCtx db) =>
{
    var token = request.Headers.Authorization.ToString();

    if (token != Environment.GetEnvironmentVariable("DEV_AUTH_KEY") && await GetSession(db, token) is null)
    {
        return Results.StatusCode(403);
    }

    if (await db.CookedGood.FirstOrDefaultAsync(x => x.RecipeId == id) is not { } good) return Results.NotFound();

    db.CookedGood.Remove(good);
    await db.SaveChangesAsync();

    return Results.Ok();
});



// API EXECUTION

app.Run();