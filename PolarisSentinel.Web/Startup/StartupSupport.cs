using System.Runtime.InteropServices;
using System.Security.Principal;

namespace PolarisSentinel.Web.Startup;

internal static class StartupSupport
{
    private const int AttachParentProcess = -1;

    private static bool _consoleAttached;

    public static bool HasConsole => _consoleAttached;

    public static bool TryAttachToParentConsole()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            if (AttachConsole(AttachParentProcess))
            {
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
                Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
                _consoleAttached = true;
            }
            else
            {
                _consoleAttached = GetConsoleWindow() != IntPtr.Zero;
            }
        }
        catch (Exception)
        {
            _consoleAttached = false;
        }

        return _consoleAttached;
    }

    public static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static bool CanShowDialog { get; set; }

    public static void ShowError(string caption, string message)
    {
        if (!CanShowDialog)
        {
            return;
        }

        try
        {
            System.Windows.Forms.MessageBox.Show(
                message,
                caption,
                System.Windows.Forms.MessageBoxButtons.OK,
                System.Windows.Forms.MessageBoxIcon.Error);
        }
        catch (Exception)
        {
        }
    }

    public static bool AskToContinue(string caption, string message)
    {
        if (!CanShowDialog)
        {
            return true;
        }

        try
        {
            return System.Windows.Forms.MessageBox.Show(
                message,
                caption,
                System.Windows.Forms.MessageBoxButtons.YesNo,
                System.Windows.Forms.MessageBoxIcon.Warning) == System.Windows.Forms.DialogResult.Yes;
        }
        catch (Exception)
        {
            return true;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(int processId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();
}
