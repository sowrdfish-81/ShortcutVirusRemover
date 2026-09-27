using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ShortcutVirusRemover
{
    class Settings
    {
        public bool RealTime = true;
        public bool ScanUsb = true;
        public int ScansDone;
        public int ThreatsRemoved;
        public string LastScan = "";
    }

    // everything lives under %LOCALAPPDATA%\ShortcutVirusRemover
    static class AppData
    {
        public static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ShortcutVirusRemover");
        public static readonly string QuarantineDir = Path.Combine(Root, "quarantine");
        public static readonly string LogsDir = Path.Combine(Root, "logs");
        public static readonly string ReportsDir = Path.Combine(Root, "reports");

        static Settings current = new Settings();
        static readonly object FileGate = new object();
        static readonly List<string> whitelist = new List<string>();

        public static Settings Settings { get { return current; } }

        static AppData()
        {
            try
            {
                Directory.CreateDirectory(QuarantineDir);
                Directory.CreateDirectory(LogsDir);
                Directory.CreateDirectory(ReportsDir);
                LoadSettings();
                LoadWhitelist();
            }
            catch { }
        }

        static string SettingsFile { get { return Path.Combine(Root, "settings.txt"); } }
        static string WhitelistFile { get { return Path.Combine(Root, "whitelist.txt"); } }

        static void LoadSettings()
        {
            if (!File.Exists(SettingsFile)) return;
            lock (FileGate)
            {
                var s = new Settings();
                foreach (string raw in File.ReadAllLines(SettingsFile))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                    string value = line.Substring(eq + 1).Trim();
                    switch (key)
                    {
                        case "realtime": s.RealTime = value == "true"; break;
                        case "scanusb": s.ScanUsb = value == "true"; break;
                        case "scansdone": int.TryParse(value, out s.ScansDone); break;
                        case "threatsremoved": int.TryParse(value, out s.ThreatsRemoved); break;
                        case "lastscan": s.LastScan = value; break;
                    }
                }
                current = s;
            }
        }

        public static void SaveSettings()
        {
            var sb = new StringBuilder();
            sb.AppendLine("# Shortcut Virus Remover settings");
            sb.AppendLine("realtime=" + (current.RealTime ? "true" : "false"));
            sb.AppendLine("scanusb=" + (current.ScanUsb ? "true" : "false"));
            sb.AppendLine("scansdone=" + current.ScansDone);
            sb.AppendLine("threatsremoved=" + current.ThreatsRemoved);
            sb.AppendLine("lastscan=" + current.LastScan);
            try { lock (FileGate) File.WriteAllText(SettingsFile, sb.ToString()); }
            catch { }
        }

        static void LoadWhitelist()
        {
            if (!File.Exists(WhitelistFile)) return;
            lock (FileGate)
            {
                whitelist.Clear();
                foreach (string raw in File.ReadAllLines(WhitelistFile))
                {
                    string line = raw.Trim();
                    if (line.Length > 0) whitelist.Add(line);
                }
            }
        }

        public static void AddWhitelist(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            lock (FileGate)
            {
                foreach (string w in whitelist)
                    if (string.Equals(w, path, StringComparison.OrdinalIgnoreCase)) return;
                whitelist.Add(path);
                try { File.WriteAllLines(WhitelistFile, whitelist); } catch { }
            }
        }

        public static List<string> WhitelistSnapshot()
        {
            lock (FileGate) return new List<string>(whitelist);
        }

        public static void RemoveWhitelist(string path)
        {
            lock (FileGate)
            {
                whitelist.RemoveAll(x => string.Equals(x, path, StringComparison.OrdinalIgnoreCase));
                try { File.WriteAllLines(WhitelistFile, whitelist); } catch { }
            }
        }

        public static bool IsWhitelisted(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            lock (FileGate)
            {
                foreach (string w in whitelist)
                    if (string.Equals(w, path, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public static void Log(string line)
        {
            try
            {
                lock (FileGate)
                    File.AppendAllText(Path.Combine(LogsDir, "log-" + DateTime.Now.ToString("yyyy-MM-dd") + ".txt"),
                        DateTime.Now.ToString("HH:mm:ss") + "  " + line + Environment.NewLine);
            }
            catch { }
        }

        public static string WriteReport(ScanContext ctx, ScanOptions opts)
        {
            try
            {
                string file = Path.Combine(ReportsDir, "report-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt");
                var sb = new StringBuilder();
                sb.AppendLine("Shortcut Virus Remover - scan report");
                sb.AppendLine("Date: " + DateTime.Now);
                sb.AppendLine("Scan type: " + opts.Kind + (opts.Kind == ScanKind.Folder ? " (" + opts.CustomFolder + ")" : ""));
                sb.AppendLine("Items checked: " + ctx.FileCount);
                sb.AppendLine("Findings: " + ctx.Found.Count);
                sb.AppendLine();
                foreach (Finding f in ctx.Found)
                    sb.AppendLine("[" + f.Severity + "] " + f.TypeName + " - " + f.Path + (f.Detail.Length > 0 ? " (" + f.Detail + ")" : ""));
                lock (FileGate) File.WriteAllText(file, sb.ToString());
                return file;
            }
            catch { return null; }
        }
    }
}
