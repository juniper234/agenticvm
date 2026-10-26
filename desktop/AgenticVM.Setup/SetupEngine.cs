using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;

namespace AgenticVM.Setup;

internal static class SetupEngine
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLink(string newLink, string existing, IntPtr security);

    public const string AppName = "AgenticVM";
    private const string RunningAppError = "Close AgenticVM before installing or updating.";

    public static string DefaultInstallDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            AppName, "App");

    public static string PayloadDirectory(string setupDirectory) =>
        Path.Combine(setupDirectory, "payload", "AgenticVM");

    public static InstallResult Install(string setupDirectory, string? installDirectory, bool shortcuts,
        Action<string>? progress = null)
    {
        var payload = PayloadDirectory(setupDirectory);
        var target = string.IsNullOrWhiteSpace(installDirectory) ? DefaultInstallDirectory : Path.GetFullPath(installDirectory);
        var required = new[]
        {
            Path.Combine(payload, "AgenticVM.exe"),
            Path.Combine(payload, "bundle", "python", "python.exe"),
            Path.Combine(payload, "bundle", "runtime", "linux-desktop", "rootfs.ext2"),
        };
        foreach (var path in required)
        {
            if (!File.Exists(path)) throw new SetupException("The installer payload is incomplete:\n" + path);
        }
        if (Process.GetProcessesByName("AgenticVM").Length > 0)
            throw new SetupException(RunningAppError);

        var total = Directory.EnumerateFiles(payload, "*", SearchOption.AllDirectories).Sum(file => new FileInfo(file).Length);
        var parent = Directory.GetParent(target)?.FullName
                     ?? throw new SetupException("The install path has no parent directory.");
        Directory.CreateDirectory(parent);
        var drive = new DriveInfo(Path.GetPathRoot(parent)!);
        if (drive.AvailableFreeSpace < total + 64L * 1024 * 1024)
            throw new SetupException($"Not enough free space. Need about {total / 1024.0 / 1024.0:N0} MB.");

        var temporary = Path.Combine(parent, ".agenticvm-install-" + Guid.NewGuid().ToString("N"));
        var old = Path.Combine(parent, ".agenticvm-old-" + Guid.NewGuid().ToString("N"));
        var log = new StringBuilder();
        log.AppendLine($"payload={payload}");
        log.AppendLine($"target={target}");
        try
        {
            progress?.Invoke("Preparing files…");
            CopyTree(payload, temporary, progress);
            if (!File.Exists(Path.Combine(temporary, "AgenticVM.exe")))
                throw new SetupException("The copied application is missing AgenticVM.exe.");

            if (Directory.Exists(target))
            {
                progress?.Invoke("Replacing previous installation…");
                Directory.Move(target, old);
            }
            Directory.Move(temporary, target);
            if (Directory.Exists(old)) Directory.Delete(old, recursive: true);

            if (shortcuts)
            {
                progress?.Invoke("Creating shortcuts…");
                CreateShortcuts(target);
            }
            var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                AppName, "install.log");
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
                File.AppendAllText(logPath, $"[{DateTimeOffset.Now:O}]\n{log}\n", Encoding.UTF8);
            }
            catch
            {
                // Logging is best-effort; the installed app is already in place.
            }
            return new InstallResult(target, total, true);
        }
        catch
        {
            TryDelete(temporary);
            if (Directory.Exists(old) && !Directory.Exists(target))
            {
                try { Directory.Move(old, target); } catch { }
            }
            throw;
        }
    }

    public static string? ShortcutPath(bool desktop)
    {
        var folder = desktop
            ? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Start Menu", "Programs");
        return string.IsNullOrWhiteSpace(folder) ? null : Path.Combine(folder, "AgenticVM.lnk");
    }

    private static void CreateShortcuts(string target)
    {
        var exe = Path.Combine(target, "AgenticVM.exe");
        if (!File.Exists(exe)) throw new SetupException("Installed executable is missing.");
        foreach (var desktop in new[] { true, false })
        {
            var path = ShortcutPath(desktop);
            if (path is null) continue;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var shellType = Type.GetTypeFromProgID("WScript.Shell")
                            ?? throw new SetupException("Windows shortcut service is unavailable.");
            dynamic shell = Activator.CreateInstance(shellType)!;
            var shortcut = shell.CreateShortcut(path);
            shortcut.TargetPath = exe;
            shortcut.WorkingDirectory = target;
            shortcut.IconLocation = exe + ",0";
            shortcut.Description = "AgenticVM native desktop";
            shortcut.Save();
        }
    }

    private static void CopyTree(string source, string target, Action<string>? progress)
    {
        var files = Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories).ToList();
        long copied = 0;
        var total = files.Sum(file => new FileInfo(file).Length);
        var index = 0;
        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(source, file);
            var destination = Path.Combine(target, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            if (Environment.GetEnvironmentVariable("AGENTICVM_INSTALL_HARDLINK") != "1"
                || !CreateHardLink(destination, file, IntPtr.Zero))
            {
                File.Copy(file, destination, overwrite: true);
            }
            copied += new FileInfo(file).Length;
            index++;
            if (index % 20 == 0 || index == files.Count)
                progress?.Invoke($"Installing… {copied * 100 / Math.Max(1, total)}%");
        }
    }

    private static void TryDelete(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
        catch { }
    }
}

internal sealed record InstallResult(string InstallDirectory, long Bytes, bool Success);

internal sealed class SetupException(string message) : Exception(message);
