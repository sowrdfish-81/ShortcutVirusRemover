using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace ShortcutVirusRemover
{
    static class Program
    {
        public const string AppVersion = "1.0.0.0";

        [DllImport("kernel32.dll")]
        static extern bool AttachConsole(int processId);

        [STAThread]
        static void Main(string[] args)
        {
            // headless mode for scripted scans, --console --full / --folder <path> [--autoclean]
            if (args.Any(a => a.Equals("--console", StringComparison.OrdinalIgnoreCase)))
            {
                AttachConsole(-1);
                ConsoleMain(args);
                return;
            }

            bool created;
            using (Mutex mutex = new Mutex(true, "ShortcutVirusRemover_Instance", out created))
            {
                if (!created)
                {
                    Native.TryBringToFront("Shortcut Virus Remover");
                    MessageBox.Show("Shortcut Virus Remover is already running. Check the system tray.", "Already running",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.ThreadException += (s, e) => AppData.Log("UI error: " + e.Exception.Message);
                Application.Run(new MainForm());
            }
        }

        static void ConsoleMain(string[] args)
        {
            bool full = args.Any(a => a.Equals("--full", StringComparison.OrdinalIgnoreCase));
            bool autoclean = args.Any(a => a.Equals("--autoclean", StringComparison.OrdinalIgnoreCase));
            string folder = null;
            int i = Array.IndexOf(args, "--folder");
            if (i >= 0 && i + 1 < args.Length) folder = args[i + 1];

            var opts = new ScanOptions();
            if (folder != null) { opts.Kind = ScanKind.Folder; opts.CustomFolder = folder; }
            else opts.Kind = full ? ScanKind.Full : ScanKind.Quick;

            var ctx = new ScanContext();
            ctx.Status = delegate { };
            ctx.Log = s => { try { Console.WriteLine(s); } catch { } };
            ScanEngine.RunScan(opts, ctx);

            foreach (Finding f in ctx.Found)
                Console.WriteLine("[" + (f.Severity == Severity.Critical ? "CRIT" : f.Severity == Severity.Suspicious ? "SUSP" : "INFO") + "] "
                    + f.TypeName + " | " + f.Path + (f.Detail.Length > 0 ? " | " + f.Detail : ""));
            Console.WriteLine("Total: " + ctx.Found.Count);

            if (autoclean && ctx.Found.Count > 0)
            {
                if (!Engine.IsElevated())
                    Console.WriteLine("Note: not running as administrator, system-level items will be skipped.");
                FixResult r = Fixer.Fix(ctx.Found, s => Console.WriteLine(s));
                Console.WriteLine("Fixed " + r.Fixed + ", failed " + r.Failed);

                var after = new ScanContext();
                after.Status = delegate { };
                after.Log = s => Console.WriteLine(s);
                ScanEngine.RunScan(opts, after);
                Console.WriteLine("After clean: " + after.Found.Count + " remaining");
            }
        }
    }

    static class Native
    {
        [DllImport("user32.dll")]
        static extern IntPtr FindWindow(string className, string title);

        [DllImport("user32.dll")]
        static extern bool SetForegroundWindow(IntPtr window);

        public static void TryBringToFront(string title)
        {
            try
            {
                IntPtr w = FindWindow(null, title);
                if (w != IntPtr.Zero) SetForegroundWindow(w);
            }
            catch { }
        }
    }
}
