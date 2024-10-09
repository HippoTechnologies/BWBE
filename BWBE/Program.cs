// ReSharper disable MoveLocalFunctionAfterJumpStatement

// IMPORTS

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BWBE.Bodies;
using BWBE.Data;
using BWBE.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

// FUNCTIONS

string Sha256Hash(string value) =>
    string.Concat(SHA256.HashData(Encoding.UTF8.GetBytes(value)).Select(item => item.ToString("x2")));

// API SETUP
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<BakeryCtx>();

builder.Services.AddAuthentication("default")
    .AddCookie("default");
builder.Services.AddAuthorization();

builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.UseSwagger();
app.UseSwaggerUI(options => options.DefaultModelsExpandDepth(-1));

// ENDPOINT MAPPINGS

// CREATES A NEW SESSION - INVALIDATING PRE-EXISTING SESSIONS
app.MapPost("/api/login", async (HttpContext ctx, Login login, BakeryCtx db) =>
{
    if (await db.User.FirstOrDefaultAsync(x => x.Username == login.Username) is not { } user) return Results.NotFound();

    if (Sha256Hash(login.Password + user.PassSalt) != user.PassHash) return Results.NotFound();

    var sessionId = Guid.NewGuid().ToString();

    if ((user.Perms & 1) == 1)
    {
        await ctx.SignInAsync("default", new ClaimsPrincipal(
            new ClaimsIdentity([new Claim(ClaimTypes.Authentication, sessionId)], "default")
        ));
    }
    else
    {
        await ctx.SignInAsync("default", new ClaimsPrincipal(
            new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, sessionId)], "default")
        ));
    }

    if (await db.Session.FirstOrDefaultAsync(o => o.UserId == user.Id) is { } deletedSession)
    {
        db.Remove(deletedSession);
        await db.SaveChangesAsync();
    }

    var session = new Session
    {
        Id = sessionId,
        UserId = user.Id,
        CreationDate = DateTime.Now,
        LastActiveDate = DateTime.Now
    };

    // ADD THE SESSION TO THE DATABASE
    db.Add(session);
    await db.SaveChangesAsync();

    return Results.Created($"/user/{user.Id}", session);
});

app.MapPost("/api/register/user", async (UserInit init, BakeryCtx db) =>
{
    var salt = Guid.NewGuid().ToString();
    // CREATE USER FROM PASSED INIT BODY
    var user = new User
    {
        Id = Guid.NewGuid().ToString(),
        FirstName = init.FirstName,
        LastName = init.LastName,
        Username = init.Username,
        PassHash = Sha256Hash(init.Password + salt),
        PassSalt = salt,
        Perms = init.Perms
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

app.MapPost("/api/register/emails", async (HttpContext httpCtx, EmailInit init, BakeryCtx db) =>
{
    if (httpCtx.Features.Get<IAuthenticateResultFeature>() is not { } feature) return Results.StatusCode(500);
    if (feature.AuthenticateResult?.Ticket is not { } ticket) return Results.StatusCode(500);

    var sessionId = ticket.Principal.Claims.First().Value;

    if (db.Session.FirstOrDefault(o => o.Id == sessionId) is not { } session) return Results.StatusCode(500);
    if (db.User.FirstOrDefault(o => o.Id == session.UserId) is not { } user) return Results.StatusCode(500);

    var email = new Email
    {
        Id = Guid.NewGuid().ToString(),
        Address = init.Address,
        UserId = user.Id,
        Verified = false
    };

    db.Email.Add(email);
    await db.SaveChangesAsync();

    return Results.Created($"/api/emails/{user.Id}", email);
});

app.MapPost("/api/register/phone", async (HttpContext httpCtx, PhoneInit init, BakeryCtx db) =>
{
    if (httpCtx.Features.Get<IAuthenticateResultFeature>() is not { } feature) return Results.StatusCode(500);
    if (feature.AuthenticateResult?.Ticket is not { } ticket) return Results.StatusCode(500);

    var sessionId = ticket.Principal.Claims.First().Value;

    if (db.Session.FirstOrDefault(o => o.Id == sessionId) is not { } session) return Results.StatusCode(500);
    if (db.User.FirstOrDefault(o => o.Id == session.UserId) is not { } user) return Results.StatusCode(500);

    var phone = new PhoneNumber
    {
        Id = Guid.NewGuid().ToString(),
        CountryCode = init.CountryCode,
        Number = init.Number,
        UserId = user.Id,
        Verified = false
    };

    db.PhoneNumber.Add(phone);
    await db.SaveChangesAsync();

    return Results.Created($"/api/phones/{user.Id}", phone);
});

app.MapGet("/api/users", async (BakeryCtx ctx) => await ctx.User.ToListAsync())
    .RequireAuthorization(o => o.RequireClaim(ClaimTypes.Authentication));

app.MapGet("/api/users/{id}", [Authorize] async (string id, HttpContext ctx, BakeryCtx db) =>
{
    if (ctx.Features.Get<IAuthenticateResultFeature>() is not { } feature) return Results.StatusCode(500);
    if (feature.AuthenticateResult?.Ticket is not { } ticket) return Results.StatusCode(500);

    var sessionId = ticket.Principal.Claims.First().Value;

    if (await db.Session.FirstOrDefaultAsync(o => o.Id == sessionId) is not { } session) return Results.StatusCode(500);
    if (await db.User.FirstOrDefaultAsync(o => o.Id == id) is not { } user) return Results.StatusCode(500);

    if (session.UserId != user.Id && ticket.Principal.Claims.First().Type == ClaimTypes.Authentication)
        return Results.Ok(user);

    if (session.UserId != user.Id) return Results.Unauthorized();

    return user.Id != id && ticket.Principal.Claims.First().Type != ClaimTypes.Authentication
        ? Results.Unauthorized()
        : Results.Ok(user);
});

app.MapGet("/api/sessions", async (BakeryCtx db) => await db.Session.ToListAsync())
    .RequireAuthorization(o => o.RequireClaim(ClaimTypes.Authentication));

app.MapGet("/api/sessions/{id}", [Authorize] async (HttpContext httpCtx, string id, BakeryCtx db) =>
{
    if (httpCtx.Features.Get<IAuthenticateResultFeature>() is not { } feature) return Results.StatusCode(500);
    if (feature.AuthenticateResult?.Ticket is not { } ticket) return Results.StatusCode(500);

    var sessionId = ticket.Principal.Claims.First().Value;

    if (sessionId != id && ticket.Principal.Claims.First().Type == ClaimTypes.Authentication)
        return Results.Ok(await db.Session.FirstOrDefaultAsync(o => o.Id == sessionId));

    return sessionId != id
        ? Results.Unauthorized()
        : Results.Ok(await db.Session.FirstOrDefaultAsync(o => o.Id == sessionId));
});

app.MapGet("/api/emails", async (BakeryCtx db) => await db.Email.ToListAsync())
    .RequireAuthorization(o => o.RequireClaim(ClaimTypes.Authentication));

app.MapGet("/api/phones", async (BakeryCtx db) => await db.PhoneNumber.ToListAsync())
    .RequireAuthorization(o => o.RequireClaim(ClaimTypes.Authentication));

app.MapGet("/api/inventory", [Authorize] async (BakeryCtx db) => await db.InventoryItem.ToListAsync());

app.MapGet("/api/inventory/search/id/{id}", async (string id, BakeryCtx db) =>
    await db.InventoryItem.FirstOrDefaultAsync(o => o.Id == id) is not { } item
        ? Results.NotFound()
        : Results.Ok(item));

app.MapGet("/api/inventory/search/name/{name}", async (string name, BakeryCtx db) =>
    await db.InventoryItem.FirstOrDefaultAsync(o => o.Name == name) is not { } item
        ? Results.NotFound()
        : Results.Ok(item));

// API EXECUTION

app.Run();