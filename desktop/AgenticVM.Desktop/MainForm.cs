using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace AgenticVM.Desktop;

// One shared interface for the browser and native app. The native layer owns
// process supervision and window integration, not a second machine sidebar.
internal sealed class MainForm : Form
{
    private readonly BackendHost _backend = new();
    private readonly WebView2 _browser = new() { Dock = DockStyle.Fill, Visible = false,
        AllowExternalDrop = false, DefaultBackgroundColor = Color.Black };
    private readonly Panel _loading = new() { Dock = DockStyle.Fill, BackColor = Color.FromArgb(16, 21, 27) };
    private readonly Label _heading = new() { AutoSize = false, TextAlign = ContentAlignment.MiddleCenter,
        ForeColor = Color.FromArgb(237, 243, 244), Font = new Font("Segoe UI", 19F), Height = 50, Dock = DockStyle.Top };
    private readonly Label _detail = new() { AutoSize = false, TextAlign = ContentAlignment.TopCenter,
        ForeColor = Color.FromArgb(162, 176, 185), Height = 110, Dock = DockStyle.Top, Padding = new Padding(28, 8, 28, 0) };
    private readonly Button _retry = new() { Text = "Try again", Width = 110, Height = 38,
        FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(183, 234, 213), ForeColor = Color.FromArgb(20, 44, 39), Visible = false };
    private readonly Panel _center = new() { Width = 600, Height = 225 };
    private string? _url;
    private bool _initializing, _closing, _fullscreen;
    private FormBorderStyle _borderBeforeFullscreen;
    private FormWindowState _stateBeforeFullscreen;

    public MainForm()
    {
        Text = "AgenticVM";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(900, 660);
        Size = new Size(1460, 940);
        BackColor = Color.Black;
        ForeColor = Color.FromArgb(237, 243, 244);
        Font = new Font("Segoe UI", 10F);
        DoubleBuffered = true;
        try { Icon = new Icon(Path.Combine(AppPaths.Root, "desktop", "AgenticVM.Desktop", "app.ico")); } catch { }
        Controls.Add(_browser);
        Controls.Add(_loading);
        _center.Controls.Add(_detail);
        _center.Controls.Add(_heading);
        _retry.Location = new Point(245, 170);
        _center.Controls.Add(_retry);
        _retry.BringToFront();
        _retry.Click += async (_, _) => await InitializeAsync();
        _loading.Controls.Add(_center);
        _loading.Resize += (_, _) => CenterLoading();
        Shown += async (_, _) => await InitializeAsync();
        FormClosing += (_, _) => { _closing = true; _backend.Dispose(); _browser.Dispose(); };
    }

    private void CenterLoading() => _center.Location = new Point(
        Math.Max(0, (_loading.ClientSize.Width - _center.Width) / 2),
        Math.Max(0, (_loading.ClientSize.Height - _center.Height) / 2));

    private void ShowLoading(string title, string detail, bool error = false)
    {
        _heading.Text = title;
        _detail.Text = detail;
        _retry.Visible = error;
        _loading.Visible = true;
        _loading.BringToFront();
        CenterLoading();
    }

    private async Task InitializeAsync()
    {
        if (_initializing || _closing) return;
        _initializing = true;
        try
        {
            ShowLoading("AgenticVM", "Opening…");
            if (!_backend.IsRunning) _url = await _backend.StartAsync();
            if (_browser.CoreWebView2 is null)
            {
                var environment = await CoreWebView2Environment.CreateAsync(null,
                    Path.Combine(AppPaths.DataDirectory, "webview2"));
                await _browser.EnsureCoreWebView2Async(environment);
                var core = _browser.CoreWebView2 ?? throw new DesktopAppException("The embedded display is unavailable.");
                core.Settings.AreDevToolsEnabled = false;
                core.Settings.AreDefaultContextMenusEnabled = false;
                core.Settings.IsStatusBarEnabled = false;
                core.Settings.AreBrowserAcceleratorKeysEnabled = true;
                await core.AddScriptToExecuteOnDocumentCreatedAsync(
                    "document.documentElement.classList.add('embedded-app');");
                core.NavigationStarting += (_, e) =>
                {
                    if (e.Uri == "about:blank") return;
                    if (_url is null || !Uri.TryCreate(e.Uri, UriKind.Absolute, out var next) ||
                        next.GetLeftPart(UriPartial.Authority) != new Uri(_url).GetLeftPart(UriPartial.Authority))
                        e.Cancel = true;
                };
                core.NewWindowRequested += (_, e) =>
                {
                    e.Handled = true;
                    if (Uri.TryCreate(e.Uri, UriKind.Absolute, out var target) && target.Scheme is "http" or "https")
                        Process.Start(new ProcessStartInfo(target.ToString()) { UseShellExecute = true });
                };
                core.NavigationCompleted += (_, e) =>
                {
                    if (_closing) return;
                    if (e.IsSuccess) { _browser.Visible = true; _loading.Visible = false; }
                    else ShowLoading("The workspace could not load", e.WebErrorStatus.ToString(), true);
                };
                core.ProcessFailed += (_, e) =>
                {
                    if (!_closing) ShowLoading("The display needs to reconnect", "Your VM is separate from this window. Try opening the viewer again.", true);
                };
                core.ContainsFullScreenElementChanged += (_, _) => SetFullscreen(core.ContainsFullScreenElement);
            }
            _browser.Source = new Uri(_url!);
        }
        catch (Exception error) { ShowLoading("The local workspace could not start", error.Message, true); }
        finally { _initializing = false; }
    }

    private void SetFullscreen(bool enabled)
    {
        if (enabled == _fullscreen) return;
        _fullscreen = enabled;
        if (enabled)
        {
            _borderBeforeFullscreen = FormBorderStyle;
            _stateBeforeFullscreen = WindowState;
            FormBorderStyle = FormBorderStyle.None;
            WindowState = FormWindowState.Maximized;
        }
        else { FormBorderStyle = _borderBeforeFullscreen; WindowState = _stateBeforeFullscreen; }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        try
        {
            int dark = 1, rounded = 2, mica = 2, caption = 0;
            DwmSetWindowAttribute(Handle, 20, ref dark, sizeof(int));
            DwmSetWindowAttribute(Handle, 33, ref rounded, sizeof(int));
            DwmSetWindowAttribute(Handle, 38, ref mica, sizeof(int));
            DwmSetWindowAttribute(Handle, 35, ref caption, sizeof(int));
        }
        catch { /* Older Windows builds retain a readable opaque frame. */ }
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
