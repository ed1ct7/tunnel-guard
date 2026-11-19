using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace TunnelGuard;

internal static class Program
{
    private const string AppName = "Tunnel Guard";

    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        var identity = WindowsIdentity.GetCurrent();
        var admin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        if (!admin)
        {
            try
            {
                var launch = new ProcessStartInfo(Environment.ProcessPath!)
                {
                    UseShellExecute = true,
                    Verb = "runas"
                };
                foreach (var arg in args)
                    launch.ArgumentList.Add(arg);
                Process.Start(launch)?.Dispose();
            }
            catch (Win32Exception exception)
            {
                string message = exception.NativeErrorCode == 1223
                    ? "Запрос прав администратора отменён. Чтобы открыть управление защитой, запусти приложение снова."
                    : $"Windows не смогла запросить права администратора.\n\n{exception.Message}";
                MessageBox.Show(message, AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            return;
        }

        using var mutex = new Mutex(true, @"Local\TunnelGuardDesktop", out bool first);
        if (!first)
        {
            MessageBox.Show("Tunnel Guard уже работает. Открой его значок рядом с часами.", AppName);
            return;
        }

        try
        {
            var app = new GuardApp(args.Contains("--repair-previous"));
            Application.Run(app);
        }
        catch (Exception exception)
        {
            MessageBox.Show(exception.Message, AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
