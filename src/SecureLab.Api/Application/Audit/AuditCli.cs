using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Audit;

// ЛР 6, advanced variant - CLI замість публічного endpoint
//   --export-audit <file>   вивантажити журнал у JSONL (рядок на запис у порядку sequence)
//   --verify-audit [<file>] перевірити БД або копію JSONL разом із файлом-якорем
// dotnet run запускає процес із теки проєкту, тому шлях до файлу краще вказувати абсолютний
// Код завершення: 0 цілий, 2 цілий із попередженням, 1 порушено або помилка
public static class AuditCli
{
    public sealed record Command(string Name, string? File);

    public static Command? Parse(string[] args)
    {
        foreach (var name in new[] { "--export-audit", "--verify-audit" })
        {
            var index = Array.IndexOf(args, name);
            if (index < 0)
                continue;
            var file = index + 1 < args.Length && !args[index + 1].StartsWith("--", StringComparison.Ordinal)
                ? args[index + 1]
                : null;
            return new Command(name, file);
        }
        return null;
    }

    public static async Task<int> RunAsync(IServiceProvider services, Command command)
    {
        try
        {
            return await RunCoreAsync(services, command);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            // Без stack trace - шлях і тип помилки достатні оператору
            Console.WriteLine($"FAIL: {exception.GetType().Name}: {exception.Message}");
            return 1;
        }
    }

    private static async Task<int> RunCoreAsync(IServiceProvider services, Command command)
    {
        await using var scope = services.CreateAsyncScope();
        var options = scope.ServiceProvider.GetRequiredService<AuditLogOptions>();
        var anchorStore = new AuditAnchorStore(options.ResolveAnchorPath());

        if (command.Name == "--export-audit")
        {
            if (command.File is null)
            {
                Console.WriteLine("Вкажіть файл: --export-audit <file>");
                return 1;
            }
            var records = await ReadDatabaseAsync(scope.ServiceProvider);
            await File.WriteAllLinesAsync(command.File, records.Select(record => JsonSerializer.Serialize(record)));
            Console.WriteLine($"Експортовано записів: {records.Count} -> {command.File}");
            return 0;
        }

        var source = command.File ?? "БД security_audit_events";
        var toVerify = command.File is null
            ? await ReadDatabaseAsync(scope.ServiceProvider)
            : (await File.ReadAllLinesAsync(command.File))
                .Where(line => !string.IsNullOrWhiteSpace(line))
                .Select(line => JsonSerializer.Deserialize<SecurityAuditEvent>(line)!)
                .ToList();
        var anchor = anchorStore.Read();
        var result = AuditChain.Verify(toVerify, anchor, options.DecodedKeys());

        Console.WriteLine($"Джерело: {source}, записів: {toVerify.Count}, останній sequence: {result.LastSequence}");
        Console.WriteLine(anchor is null
            ? "Якір: відсутній"
            : $"Якір: sequence {anchor.Sequence}, key {anchor.KeyId}, hmac {anchor.Hmac[..12]}...");
        foreach (var warning in result.Warnings)
            Console.WriteLine($"WARNING: {warning}");
        foreach (var error in result.Errors)
            Console.WriteLine($"FAIL: {error}");
        if (!result.IsValid)
            return 1;
        Console.WriteLine(result.Warnings.Count == 0 ? "PASS: ланцюжок цілий, якір збігається" : "PASS з попередженням");
        return result.Warnings.Count == 0 ? 0 : 2;
    }

    private static Task<List<SecurityAuditEvent>> ReadDatabaseAsync(IServiceProvider services) =>
        services.GetRequiredService<SecureLabDbContext>().SecurityAuditEvents.AsNoTracking()
            .OrderBy(record => record.Sequence)
            .ToListAsync();
}
