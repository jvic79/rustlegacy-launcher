using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Chave secreta igual à usada no launcher
string secretKey = "OWMxZDMzZTEtZXhlbXBsby1kZS1jaGF2ZS1zZWNyZXRh";
ConcurrentDictionary<string, DateTime> pendingAuths = new();

// Endpoint para receber o token do launcher
app.MapPost("/auth", async (HttpRequest req) =>
{
    var payload = await JsonSerializer.DeserializeAsync<AuthPayload>(req.Body);

    if (payload == null)
        return Results.BadRequest("JSON inválido");

    string expectedToken = GerarToken(payload.playerId, payload.hwid, payload.timestamp);

    if (expectedToken != payload.sessionToken)
        return Results.Unauthorized();

    pendingAuths[payload.playerId] = DateTime.UtcNow.AddMinutes(2);
    Console.WriteLine($"[✔] Autorizado: {payload.playerId}");
    return Results.Ok();
});

// (Opcional) Verificação manual pelo navegador
app.MapGet("/", () => "Servidor de autenticação online.");

// Faz o servidor aceitar conexões de fora (não só localhost)
app.Run("http://0.0.0.0:5000");

// Gera token esperado, igual ao do launcher
string GerarToken(string playerId, string hwid, string timestamp)
{
    string data = $"{playerId}|{hwid}|{timestamp}";
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
    byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    return Convert.ToBase64String(hash);
}

record AuthPayload(string playerId, string hwid, string timestamp, string sessionToken);
