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

app.MapGet("/api/sessions", async (BakeryCtx db) => await db.Session.ToListAsync())
    .RequireAuthorization(o => o.RequireClaim(ClaimTypes.Authentication));

app.MapGet("/api/sessions/{id}", [Authorize] async (HttpContext httpCtx, string id, BakeryCtx db) =>
{
    if (httpCtx.Features.Get<IAuthenticateResultFeature>() is not { } feature) return Results.StatusCode(500);
    if (feature.AuthenticateResult?.Ticket is not { } ticket) return Results.StatusCode(500);

    var sessionId = ticket.Principal.Claims.First().Value;
    return sessionId != id
        ? Results.Forbid()
        : Results.Ok(await db.Session.FirstOrDefaultAsync(o => o.Id == sessionId));
});

app.MapGet("/api/emails", async (BakeryCtx db) => await db.Email.ToListAsync())
    .RequireAuthorization(o => o.RequireClaim(ClaimTypes.Authentication));

app.MapGet("/api/users", async (BakeryCtx ctx) => await ctx.User.ToListAsync())
    .RequireAuthorization(o => o.RequireClaim(ClaimTypes.Authentication));


// API EXECUTION

app.Run();