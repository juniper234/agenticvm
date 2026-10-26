using System.Drawing.Drawing2D;
using System.Drawing.Text;

namespace AgenticVM.Desktop;

internal static class Theme
{
    public static readonly Color Paper = Color.FromArgb(16, 21, 27);
    public static readonly Color PaperHi = Color.FromArgb(248, 245, 236);
    public static readonly Color PaperLow = Color.FromArgb(230, 226, 215);
    public static readonly Color Ink = Color.FromArgb(237, 243, 244);
    public static readonly Color InkSoft = Color.FromArgb(35, 35, 32);
    public static readonly Color Line = Color.FromArgb(185, 180, 167);
    public static readonly Color LineHi = Color.FromArgb(22, 22, 19);
    public static readonly Color Text = Color.FromArgb(237, 243, 244);
    public static readonly Color Muted = Color.FromArgb(98, 94, 85);
    public static readonly Color Dim = Color.FromArgb(98, 94, 85);
    public static readonly Color Red = Color.FromArgb(201, 52, 30);
    public static readonly Color RedDeep = Color.FromArgb(158, 36, 21);
    public static readonly Color Screen = Color.FromArgb(11, 11, 10);
    public static readonly Font Font = new("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
    public static readonly Font FontSmall = new("Segoe UI", 8F, FontStyle.Regular, GraphicsUnit.Point);
    public static readonly Font FontMedium = new("Segoe UI", 9.5F, FontStyle.Regular, GraphicsUnit.Point);
    public static readonly Font FontSemibold = new("Bahnschrift", 9F, FontStyle.Regular, GraphicsUnit.Point);
    public static readonly Font FontDisplay = new("Bahnschrift Condensed", 12F, FontStyle.Bold, GraphicsUnit.Point);
    public static readonly Font FontEyebrow = new("Cascadia Mono", 7.5F, FontStyle.Bold, GraphicsUnit.Point);
    public static readonly Font FontMono = new("Cascadia Mono", 8F, FontStyle.Regular, GraphicsUnit.Point);
}

internal static class U
{
    public static void FillRounded(Graphics graphics, Brush brush, RectangleF rect, float radius)
    {
        graphics.FillRectangle(brush, rect);
    }

    public static void DrawRounded(Graphics graphics, Pen pen, RectangleF rect, float radius)
    {
        graphics.DrawRectangle(pen, rect.X, rect.Y, rect.Width, rect.Height);
    }

    public static GraphicsPath Rounded(RectangleF rect, float radius)
    {
        var path = new GraphicsPath();
        path.AddRectangle(rect);
        return path;
    }

    public static void Text(Graphics graphics, string value, Font font, Color color, Rectangle bounds,
        TextFormatFlags flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding)
    {
        TextRenderer.DrawText(graphics, value, font, bounds, color, flags);
    }
}

internal sealed class BrandMark : Control
{
    public BrandMark()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        Size = new Size(38, 38);
        BackColor = Color.Transparent;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.None;
        var box = new Rectangle(4, 4, Width - 9, Height - 9);
        using var line = new Pen(Theme.LineHi, 1f);
        g.DrawRectangle(line, box);
        g.DrawLine(line, box.Left + box.Width / 2, 0, box.Left + box.Width / 2, Height);
        g.DrawLine(line, 0, box.Top + box.Height / 2, Width, box.Top + box.Height / 2);
        using var red = new SolidBrush(Theme.Red);
        g.FillRectangle(red, box.Left + box.Width / 2 - 4, box.Top + box.Height / 2 - 4, 8, 8);
    }
}

internal sealed class Pill : Control
{
    private string _text = "";
    public Color Accent { get; set; } = Theme.Red;

    public string TextValue
    {
        get => _text;
        set { _text = value; Invalidate(); }
    }

    public Pill()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        Height = 28;
        Width = 124;
        BackColor = Color.Transparent;
        Font = Theme.FontEyebrow;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.None;
        var rect = new Rectangle(0, 0, Width - 1, Height - 1);
        using var fill = new SolidBrush(Theme.PaperHi);
        using var line = new Pen(Theme.LineHi);
        g.FillRectangle(fill, rect);
        g.DrawRectangle(line, rect);
        using var dot = new SolidBrush(Theme.Red);
        g.FillRectangle(dot, 9, Height / 2 - 3, 6, 6);
        U.Text(g, _text, Font, Theme.Text, new Rectangle(21, 0, Width - 25, Height));
    }
}

internal sealed class MachineCard : Control
{
    public bool Selected { get; set; } = true;
    public string MachineName { get; set; } = "Local Guest";
    public string Subtitle { get; set; } = "Linux / Android";
    public event EventHandler? Activated;

    public MachineCard()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        Height = 68;
        BackColor = Color.Transparent;
        Cursor = Cursors.Hand;
        Click += (_, _) => Activated?.Invoke(this, EventArgs.Empty);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.None;
        var rect = new Rectangle(0, 0, Width - 1, Height - 1);
        using var fill = new SolidBrush(Selected ? Theme.Ink : Theme.PaperLow);
        using var line = new Pen(Selected ? Theme.Ink : Theme.LineHi);
        g.FillRectangle(fill, rect);
        g.DrawRectangle(line, rect);
        var primary = Selected ? Theme.PaperHi : Theme.Ink;
        var secondary = Selected ? Color.FromArgb(190, 186, 174) : Theme.Muted;
        U.Text(g, "01", Theme.FontDisplay, Theme.Red, new Rectangle(9, 10, 28, 26));
        U.Text(g, MachineName, Theme.FontSemibold, primary, new Rectangle(38, 10, Width - 48, 22));
        U.Text(g, Subtitle, Theme.FontMono, secondary, new Rectangle(38, 34, Width - 48, 18));
        U.Text(g, "OWNED", Theme.FontEyebrow, secondary, new Rectangle(Width - 65, 10, 54, 16),
            TextFormatFlags.Right | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
    }
}

internal sealed class Spinner : Control
{
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 40 };
    private float _angle;

    public Spinner()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        Size = new Size(36, 36);
        BackColor = Color.Transparent;
        _timer.Tick += (_, _) => { _angle = (_angle + 9) % 360; Invalidate(); };
    }

    public void Start() => _timer.Start();
    public void Stop() { _timer.Stop(); Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.None;
        var box = new Rectangle(3, 3, Width - 7, Height - 7);
        using var line = new Pen(Theme.Line, 1f);
        g.DrawRectangle(line, box);
        using var red = new Pen(Theme.Red, 2f);
        g.DrawLine(red, box.Left, box.Top, box.Left + 11, box.Top);
        g.DrawLine(red, box.Right, box.Bottom, box.Right - 11, box.Bottom);
        g.TranslateTransform(Width / 2f, Height / 2f);
        g.RotateTransform(_angle);
        using var tick = new Pen(Theme.Red, 1.5f);
        g.DrawLine(tick, 0, -8, 0, -13);
        g.ResetTransform();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _timer.Dispose();
        base.Dispose(disposing);
    }
}
