using System.Text;

namespace AgenticVM.Desktop;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        var configured = Environment.GetEnvironmentVariable("AGENTICVM_APP_DATA");
        var log = Path.Combine(string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AgenticVM")
            : configured, "crash.log");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(log)!);
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetDefaultFont(Theme.Font);
            Application.ThreadException += (_, e) => Fail(log, e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                Fail(log, e.ExceptionObject as Exception ?? new Exception(e.ExceptionObject?.ToString()));
            Application.Run(new MainForm());
        }
        catch (Exception error)
        {
            Fail(log, error);
        }
    }

    private static void Fail(string log, Exception error)
    {
        try
        {
            File.AppendAllText(log,
                $"[{DateTimeOffset.Now:O}]\n{error}\n\n", Encoding.UTF8);
        }
        catch { }
        MessageBox.Show(error.Message, "AgenticVM could not start",
            MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
