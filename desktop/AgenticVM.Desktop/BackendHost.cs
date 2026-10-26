using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace AgenticVM.Desktop;

internal static class AppPaths
{
    public static string Root { get; } = FindRoot();

    private static string? _dataDirectory;

    public static string DataDirectory
    {
        get
        {
            if (_dataDirectory is not null) return _dataDirectory;
            var candidates = new List<string>();
            var configured = Environment.GetEnvironmentVariable("AGENTICVM_APP_DATA");
            if (!string.IsNullOrWhiteSpace(configured)) candidates.Add(configured);
            candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AgenticVM"));
            candidates.Add(Path.Combine(Path.GetTempPath(), "AgenticVM"));
            candidates.Add(Path.Combine(Root, "runtime", "desktop-app"));
            foreach (var candidate in candidates)
            {
                try
                {
                    Directory.CreateDirectory(candidate);
                    var probe = Path.Combine(candidate, ".write-test");
                    File.WriteAllText(probe, "ok");
                    File.Delete(probe);
                    _dataDirectory = candidate;
                    return candidate;
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
            throw new DesktopAppException(
                "No writable AgenticVM data directory was found.\n\n" +
                "Set AGENTICVM_APP_DATA to a writable folder.");
        }
    }

    public static string Python
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable("AGENTICVM_PYTHON");
            if (!string.IsNullOrWhiteSpace(configured)) return configured;
            var bundled = Path.Combine(Root, "python", "python.exe");
            if (File.Exists(bundled)) return bundled;
            return Path.Combine(Root, "tools", "python-runtime", "3.13.16", "python.exe");
        }
    }

    public static string? Qemu
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable("AGENTICVM_QEMU");
            if (!string.IsNullOrWhiteSpace(configured)) return configured;
            var bundled = Path.Combine(Root, "tools", "qemu", "11.1.0", "qemu-system-x86_64.exe");
            return File.Exists(bundled) ? bundled : null;
        }
    }

    public static string BackendScript => Path.Combine(Root, "desktop", "backend_host.py");

    private static string FindRoot()
    {
        var bundled = Path.Combine(AppContext.BaseDirectory, "bundle");
        if (IsRoot(bundled) && File.Exists(Path.Combine(bundled, "python", "python.exe"))) return bundled;

        var configured = Environment.GetEnvironmentVariable("AGENTICVM_HOME");
        if (!string.IsNullOrWhiteSpace(configured) && IsRoot(configured)) return Path.GetFullPath(configured);

        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && directory is not null; i++, directory = directory.Parent)
        {
            if (IsRoot(directory.FullName)) return directory.FullName;
        }

        throw new DesktopAppException(
            "The AgenticVM backend could not be found.\n\n" +
            "Place AgenticVM.exe inside the repository or a portable bundle " +
            "(bundle\\python, bundle\\src, bundle\\desktop), or set AGENTICVM_HOME.");
    }

    private static bool IsRoot(string path) =>
        File.Exists(Path.Combine(path, "src", "agenticvm", "viewer.py")) &&
        File.Exists(Path.Combine(path, "desktop", "backend_host.py"));
}

internal sealed class DesktopAppException(string message) : Exception(message);

internal sealed class BackendHost : IDisposable
{
    private Process? _process;
    private readonly StringBuilder _stderr = new();
    private readonly StringBuilder _stdout = new();

    public string? Url { get; private set; }
    public bool IsRunning => _process is { HasExited: false };

    public async Task<string> StartAsync(CancellationToken cancellationToken = default)
    {
        if (IsRunning && Url is not null) return Url;

        var root = AppPaths.Root;
        var python = AppPaths.Python;
        if (!File.Exists(python)) throw new DesktopAppException("Python runtime not found:\n" + python);

        var data = AppPaths.DataDirectory;
        var workspace = Path.Combine(data, "workspace");
        var logs = Path.Combine(data, "logs");
        Directory.CreateDirectory(workspace);
        Directory.CreateDirectory(logs);
        var ready = Path.Combine(data, "viewer-ready.json");
        var existing = await ExistingViewerAsync(ready, workspace, cancellationToken);
        if (existing is not null) { Url = existing; return existing; }
        if (File.Exists(ready)) File.Delete(ready);

        var start = new ProcessStartInfo
        {
            FileName = python,
            WorkingDirectory = root,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        start.ArgumentList.Add("-I");
        start.ArgumentList.Add("-B");
        start.ArgumentList.Add(AppPaths.BackendScript);
        start.ArgumentList.Add("--workspace");
        start.ArgumentList.Add(workspace);
        start.ArgumentList.Add("--session");
        start.ArgumentList.Add("desktop-app");
        start.ArgumentList.Add("--port");
        start.ArgumentList.Add("0");
        start.ArgumentList.Add("--ready-file");
        start.ArgumentList.Add(ready);
        start.ArgumentList.Add("--quiet-launch");
        start.Environment["AGENTICVM_HOME"] = root;
        var qemu = AppPaths.Qemu;
        if (qemu is not null) start.Environment["AGENTICVM_QEMU"] = qemu;

        _stderr.Clear();
        _stdout.Clear();
        _process = new Process { StartInfo = start, EnableRaisingEvents = true };
        _process.OutputDataReceived += (_, e) => { if (e.Data is not null) _stdout.AppendLine(e.Data); };
        _process.ErrorDataReceived += (_, e) => { if (e.Data is not null) _stderr.AppendLine(e.Data); };
        if (!_process.Start()) throw new DesktopAppException("The local backend did not start.");
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        var deadline = DateTime.UtcNow.AddSeconds(25);
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (File.Exists(ready))
            {
                try
                {
                    using var document = JsonDocument.Parse(await File.ReadAllTextAsync(ready, cancellationToken));
                    var url = document.RootElement.GetProperty("url").GetString();
                    if (!string.IsNullOrWhiteSpace(url))
                    {
                        Url = url;
                        return url;
                    }
                }
                catch (JsonException) { }
                catch (IOException) { }
            }
            if (_process.HasExited)
            {
                throw new DesktopAppException(
                    "The local viewer exited before it became ready.\n\n" +
                    Trim(_stderr.ToString()) + Trim(_stdout.ToString()));
            }
            await Task.Delay(150, cancellationToken);
        }

        Stop();
        throw new DesktopAppException(
            "The local viewer did not become ready within 25 seconds.\n\n" +
            Trim(_stderr.ToString()) + Trim(_stdout.ToString()));
    }

    public void Stop()
    {
        var process = _process;
        _process = null;
        if (process is null) return;
        try
        {
            // VM processes have persistent ownership receipts and outlive the
            // viewer. Closing a window must not force off a running guest.
            if (!process.HasExited) process.Kill(entireProcessTree: false);
        }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { }
        finally
        {
            process.Dispose();
        }
    }

    private static async Task<string?> ExistingViewerAsync(string ready, string workspace, CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(ready) || new FileInfo(ready).Length > 4096) return null;
            using var receipt = JsonDocument.Parse(await File.ReadAllTextAsync(ready, cancellationToken));
            var url = receipt.RootElement.GetProperty("url").GetString();
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "http" ||
                uri.Host != "127.0.0.1" || uri.AbsolutePath != "/" || uri.UserInfo.Length != 0 ||
                uri.Query.Length != 0 || !uri.Fragment.StartsWith("#token=")) return null;
            var token = uri.Fragment[7..];
            if (token.Length is < 30 or > 128 || token.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')) return null;
            using var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2) };
            client.DefaultRequestHeaders.Add("X-AgenticVM-Token", token);
            using var response = await client.GetAsync(uri.GetLeftPart(UriPartial.Authority) + "/api/info", cancellationToken);
            if (response.StatusCode != HttpStatusCode.OK) return null;
            using var info = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            if (!info.RootElement.GetProperty("ok").GetBoolean()) return null;
            var result = info.RootElement.GetProperty("result");
            var session = result.GetProperty("session").GetString();
            if (result.GetProperty("name").GetString() != "AgenticVM" ||
                !string.Equals(result.GetProperty("workspace").GetString(), Path.GetFullPath(workspace), StringComparison.OrdinalIgnoreCase) ||
                session is not ("desktop-app" or "desktop-app-android" or "desktop-app-windows")) return null;
            return url;
        }
        catch (Exception error) when (error is IOException or JsonException or HttpRequestException or TaskCanceledException or InvalidOperationException or KeyNotFoundException)
        {
            return null;
        }
    }

    private static string Trim(string value) =>
        string.IsNullOrWhiteSpace(value) ? "" : value.Trim().Length > 1600 ? value.Trim()[^1600..] : value.Trim();

    public void Dispose() => Stop();
}
