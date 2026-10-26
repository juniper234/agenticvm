using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Text;

namespace AgenticVM.Setup;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        var setupDirectory = AppContext.BaseDirectory;
        var installDirectory = Argument(args, "--install-dir=")
                               ?? Environment.GetEnvironmentVariable("AGENTICVM_INSTALL_DIR");
        var silent = args.Contains("--silent", StringComparer.OrdinalIgnoreCase);
        var noShortcuts = args.Contains("--no-shortcuts", StringComparer.OrdinalIgnoreCase);
        if (silent)
        {
            try
            {
                var result = SetupEngine.Install(setupDirectory, installDirectory, !noShortcuts);
                WriteResult(Path.Combine(setupDirectory, "setup-result.json"),
                    $"{{\"ok\":true,\"target\":{Json(result.InstallDirectory)},\"bytes\":{result.Bytes}}}\n");
                Environment.ExitCode = 0;
            }
            catch (Exception error)
            {
                WriteResult(Path.Combine(setupDirectory, "setup-result.json"),
                    $"{{\"ok\":false,\"error\":{Json(error.Message)}}}\n");
                Environment.ExitCode = 1;
            }
            return;
        }

        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetDefaultFont(new Font("Segoe UI", 9F));
        Application.Run(new SetupForm(setupDirectory, installDirectory, !noShortcuts));
    }

    private static void WriteResult(string path, string payload)
    {
        try { File.WriteAllText(path, payload); }
        catch { }
    }

    private static string? Argument(string[] args, string prefix) =>
        args.FirstOrDefault(value => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))?[prefix.Length..];

    private static string Json(string value) =>
        "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
}

internal sealed class SetupForm : Form
{
    private readonly string _setupDirectory;
    private readonly string _installDirectory;
    private readonly bool _createShortcuts;
    private readonly Label _status;
    private readonly ProgressBar _progress;
    private readonly Button _install;
    private readonly Button _close;
    private string? _installed;
    private bool _busy;

    public SetupForm(string setupDirectory, string? installDirectory, bool createShortcuts)
    {
        _setupDirectory = setupDirectory;
        _installDirectory = installDirectory ?? SetupEngine.DefaultInstallDirectory;
        _createShortcuts = createShortcuts;
        Text = "AgenticVM Setup";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(660, 392);
        MinimumSize = MaximumSize = Size;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        BackColor = Color.FromArgb(240, 237, 228);
        ForeColor = Color.FromArgb(17, 17, 16);
        Font = new Font("Segoe UI", 9F);
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

        var header = new Panel { Dock = DockStyle.Top, Height = 104, BackColor = Color.FromArgb(248, 245, 236) };
        header.Paint += (_, e) =>
        {
            using var pen = new Pen(Color.FromArgb(185, 180, 167));
            e.Graphics.DrawLine(pen, 0, header.Height - 1, header.Width, header.Height - 1);
        };
        var mark = new BrandMark { Location = new Point(28, 28) };
        header.Controls.Add(mark);
        header.Controls.Add(new Label
        {
            Text = "AGENTICVM / FIELD CONSOLE",
            Location = new Point(100, 25),
            AutoSize = true,
            ForeColor = Color.FromArgb(98, 94, 85),
            Font = new Font("Cascadia Mono", 7.5F, FontStyle.Bold),
        });
        header.Controls.Add(new Label
        {
            Text = "Install the native desktop",
            Location = new Point(98, 42),
            AutoSize = true,
            ForeColor = Color.FromArgb(17, 17, 16),
            Font = new Font("Bahnschrift Condensed", 16F, FontStyle.Bold),
        });

        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(28, 22, 28, 0) };
        body.Controls.Add(new Label
        {
            Text = "A per-user install. No administrator rights, service, firewall or host-network changes.",
            Location = new Point(0, 0),
            AutoSize = true,
            ForeColor = Color.FromArgb(98, 94, 85),
        });
        body.Controls.Add(new Label
        {
            Text = "INSTALL LOCATION",
            Location = new Point(0, 34),
            AutoSize = true,
            ForeColor = Color.FromArgb(98, 94, 85),
            Font = new Font("Cascadia Mono", 7.5F, FontStyle.Bold),
        });
        body.Controls.Add(new Label
        {
            Text = _installDirectory,
            Location = new Point(0, 53),
            Width = 600,
            Height = 24,
            AutoEllipsis = true,
            ForeColor = Color.FromArgb(17, 17, 16),
            BackColor = Color.FromArgb(230, 226, 215),
            Padding = new Padding(8, 3, 8, 3),
        });
        body.Controls.Add(new Label
        {
            Text = "The payload contains Python, QEMU, the desktop image and the native shell (about 1.7 GB).",
            Location = new Point(0, 86),
            AutoSize = true,
            ForeColor = Color.FromArgb(98, 94, 85),
        });
        body.Controls.Add(new Label
        {
            Text = "VM data stays under %LOCALAPPDATA%\\AgenticVM and is not overwritten by an app update.",
            Location = new Point(0, 108),
            AutoSize = true,
            ForeColor = Color.FromArgb(98, 94, 85),
        });

        _status = new Label
        {
            Text = "Ready to install.",
            Location = new Point(0, 154),
            Width = 600,
            Height = 22,
            ForeColor = Color.FromArgb(98, 94, 85),
        };
        body.Controls.Add(_status);
        _progress = new ProgressBar
        {
            Location = new Point(0, 181),
            Width = 600,
            Height = 8,
            Style = ProgressBarStyle.Continuous,
            Value = 0,
        };
        body.Controls.Add(_progress);

        _install = Button("Install AgenticVM", 172, primary: true);
        _install.Location = new Point(0, 214);
        _install.Click += async (_, _) => await InstallAsync();
        body.Controls.Add(_install);
        var cancel = Button("Cancel", 94);
        cancel.Location = new Point(182, 214);
        cancel.Click += (_, _) => Close();
        body.Controls.Add(cancel);
        _close = cancel;

        Controls.Add(body);
        Controls.Add(header);
        FormClosing += (_, e) =>
        {
            if (_busy)
            {
                e.Cancel = true;
                MessageBox.Show("Installation is still running.", "AgenticVM Setup",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        };
        Shown += (_, _) => { try { TryDarkTitleBar(); } catch { } };
    }

    private async Task InstallAsync()
    {
        if (_busy) return;
        _busy = true;
        _install.Enabled = false;
        _close.Enabled = false;
        _progress.Style = ProgressBarStyle.Marquee;
        _status.Text = "Installing…";
        try
        {
            var result = await Task.Run(() => SetupEngine.Install(_setupDirectory, _installDirectory, _createShortcuts,
                text => BeginInvoke(() => { _status.Text = text; })));
            _installed = result.InstallDirectory;
            _progress.Style = ProgressBarStyle.Continuous;
            _progress.Value = 100;
            _status.Text = "Installed. Launch AgenticVM from the Desktop or Start Menu.";
            _install.Text = "Launch AgenticVM";
            _install.Enabled = true;
            _install.Click -= InstallHandler;
            _install.Click += InstallHandler;
            _close.Text = "Close";
            _close.Enabled = true;
        }
        catch (Exception error)
        {
            _progress.Style = ProgressBarStyle.Continuous;
            _progress.Value = 0;
            _status.Text = error.Message;
            _status.ForeColor = Color.FromArgb(255, 210, 210);
            _install.Enabled = true;
            _close.Enabled = true;
        }
        finally
        {
            _busy = false;
        }
    }

    private void InstallHandler(object? sender, EventArgs e)
    {
        if (_installed is null) return;
        try
        {
            Process.Start(new ProcessStartInfo(Path.Combine(_installed, "AgenticVM.exe")) { UseShellExecute = true });
            Close();
        }
        catch (Exception error)
        {
            MessageBox.Show(error.Message, "AgenticVM Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private static Button Button(string text, int width, bool primary = false) => new()
    {
        Text = text,
        Width = width,
        Height = 34,
        FlatStyle = FlatStyle.Flat,
        FlatAppearance = { BorderSize = 1, BorderColor = Color.FromArgb(22, 22, 19), MouseOverBackColor = Color.FromArgb(230, 226, 215) },
        BackColor = primary ? Color.FromArgb(201, 52, 30) : Color.FromArgb(248, 245, 236),
        ForeColor = primary ? Color.White : Color.FromArgb(17, 17, 16),
        Font = new Font("Cascadia Mono", 8F, FontStyle.Bold),
    };

    private void TryDarkTitleBar()
    {
        var dark = 0;
        DwmSetWindowAttribute(Handle, 20, ref dark, sizeof(int));
        var rounded = 1;
        DwmSetWindowAttribute(Handle, 33, ref rounded, sizeof(int));
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}

internal sealed class BrandMark : Control
{
    public BrandMark()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.SupportsTransparentBackColor, true);
        Size = new Size(48, 48);
        BackColor = Color.Transparent;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.None;
        var box = new Rectangle(4, 4, Width - 9, Height - 9);
        using var line = new Pen(Color.FromArgb(22, 22, 19), 1f);
        g.DrawRectangle(line, box);
        g.DrawLine(line, box.Left + box.Width / 2, 0, box.Left + box.Width / 2, Height);
        g.DrawLine(line, 0, box.Top + box.Height / 2, Width, box.Top + box.Height / 2);
        using var red = new SolidBrush(Color.FromArgb(201, 52, 30));
        g.FillRectangle(red, box.Left + box.Width / 2 - 5, box.Top + box.Height / 2 - 5, 10, 10);
    }
}
