using System.Text.Json;

namespace SecureLab.Api.Application.Audit;

// ЛР 6, advanced variant - номер і HMAC останнього запису в окремому локальному файлі поза БД
public sealed class AuditAnchorStore(string path)
{
    public string Path { get; } = path;

    public AuditAnchor? Read()
    {
        if (!File.Exists(Path))
            return null;
        return JsonSerializer.Deserialize<AuditAnchor>(File.ReadAllText(Path));
    }

    // Атомарна заміна - спершу тимчасовий файл, потім move поверх старого
    public void Write(AuditAnchor anchor)
    {
        var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(Path));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
        var temporary = Path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(anchor));
        File.Move(temporary, Path, overwrite: true);
    }

    public void Delete()
    {
        if (File.Exists(Path))
            File.Delete(Path);
    }
}
