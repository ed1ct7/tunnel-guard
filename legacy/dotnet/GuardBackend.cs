using System.Diagnostics;
using System.Text;
using System.Text.Json;
using YamlDotNet.RepresentationModel;

namespace TunnelGuard;

internal sealed record Settings(string ClientPath = "", string Adapter = "Mihomo", int ProxyPort = 10808);

internal static class GuardBackend
{
    private static readonly string Data = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelGuard");
    private static readonly string Config = Path.Combine(Data, "settings.json");

    public static Settings LoadSettings() =>
        File.Exists(Config) ? JsonSerializer.Deserialize<Settings>(File.ReadAllText(Config)) ?? new() : new();

    public static void SaveSettings(Settings settings)
    {
        Directory.CreateDirectory(Data);
        WriteFile(Config, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
    }

    public static async Task<string> Run(string action)
    {
        Directory.CreateDirectory(Data);
        var script = Path.Combine(Data, "Firewall.ps1");
        using var resource = typeof(GuardBackend).Assembly.GetManifestResourceStream("TunnelGuard.Firewall.ps1")
            ?? throw new InvalidOperationException("В сборке отсутствует компонент брандмауэра.");
        using var reader = new StreamReader(resource);
        string bundledScript = reader.ReadToEnd();
        if (!File.Exists(script) || File.ReadAllText(script) != bundledScript)
            WriteFile(script, bundledScript);
        var info = new ProcessStartInfo(
            Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-File", script,
                     "-Action", action, "-SettingsPath", Config })
            info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Не удалось открыть брандмауэр.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        if (process.ExitCode != 0)
        {
            string detail = (await error).Trim();
            throw new InvalidOperationException(detail.Length == 0 ? $"Windows PowerShell: {process.ExitCode}" : detail);
        }
        return (await output).Trim();
    }

    public static void WriteFile(string path, string content)
    {
        string temporary = path + ".new";
        File.WriteAllText(temporary, content, new UTF8Encoding(false));
        File.Move(temporary, path, true);
    }
}

internal sealed class RoutingFile
{
    private const string Key = "prepend-rules";
    private readonly string path;
    private readonly string original;
    private readonly YamlStream stream = new();
    private readonly YamlMappingNode root;

    public RoutingFile(Settings settings)
    {
        path = Path.Combine(Path.GetDirectoryName(settings.ClientPath) ?? "", "guiConfigs", "Mixin.yaml");
        if (!File.Exists(path))
            throw new InvalidOperationException("В выбранной папке нет guiConfigs\\Mixin.yaml.");
        original = File.ReadAllText(path);
        stream.Load(new StringReader(original));
        if (stream.Documents.Count != 1 || stream.Documents[0].RootNode is not YamlMappingNode mapping)
            throw new InvalidOperationException("Mixin.yaml должен содержать одну таблицу YAML.");
        root = mapping;
    }

    public string[] ReadRules()
    {
        if (!root.Children.TryGetValue(new YamlScalarNode(Key), out var node))
            return [];
        if (node is not YamlSequenceNode sequence ||
            sequence.Children.Any(child => child is not YamlScalarNode { Value: not null }))
            throw new InvalidOperationException("prepend-rules должен быть списком строк.");
        return sequence.Children.Cast<YamlScalarNode>().Select(child => child.Value!).ToArray();
    }

    public void Save(string[] rules)
    {
        if (ReadRules().SequenceEqual(rules))
            return;
        if (File.ReadAllText(path) != original)
            throw new InvalidOperationException("Mixin.yaml изменился. Открой правила заново.");
        var mainConfig = Path.Combine(Path.GetDirectoryName(path)!, "guiNConfig.json");
        using var v2ray = JsonDocument.Parse(File.ReadAllText(mainConfig));
        var mixinOn = v2ray.RootElement.EnumerateObject()
            .Where(field => field.Name.Equals("ClashUIItem", StringComparison.OrdinalIgnoreCase))
            .SelectMany(field => field.Value.EnumerateObject())
            .Any(field => field.Name.Equals("EnableMixinContent", StringComparison.OrdinalIgnoreCase) &&
                          field.Value.ValueKind == JsonValueKind.True);
        if (!mixinOn)
            throw new InvalidOperationException("Включи Enable Mixin Content в настройках Mihomo в v2rayN.");
        root.Children[new YamlScalarNode(Key)] = new YamlSequenceNode(rules.Select(rule => new YamlScalarNode(rule)));
        var output = new StringWriter();
        stream.Save(output, assignAnchors: false);
        File.Copy(path, path + ".tunnelguard.bak", true);
        GuardBackend.WriteFile(path, output.ToString());
    }
}
