using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace ShortcutVirusRemover
{
    enum Severity { Info, Suspicious, Critical }

    enum ThreatType
    {
        WormFolder,       // sysvolume folder on a drive root
        VirusShortcut,    // .lnk that runs a script
        HiddenFolder,     // hidden+system folder planted by the worm
        WormFile,         // uXXXXXX droppers, fake-extension files, invisible names
        PayloadFolder,    // SubDir / wsvcz folders under System32
        StartupScr,       // .scr stager in a Startup folder
        BadTask,          // scheduled task pointing at malware
        BadRunKey,        // autorun registry entry
        BadExclusion,     // Defender exclusion added by the malware
        DefenderOff,      // real-time protection switched off
        MaliciousProcess,
        KnownMalware,     // SHA256 hash match
        BadAutorun        // autorun.inf that launches a script
    }

    class Finding
    {
        public ThreatType Type;
        public Severity Severity;
        public string Path = "";
        public string Detail = "";
        public string TaskPath = "";
        public string RegPath = "";
        public string RegName = "";
        public string Exclusion = "";
        public int Pid = -1;
        public bool IsDirectory;

        public string TypeName
        {
            get
            {
                switch (Type)
                {
                    case ThreatType.WormFolder: return "Worm folder";
                    case ThreatType.VirusShortcut: return "Virus shortcut";
                    case ThreatType.HiddenFolder: return "Hidden folder";
                    case ThreatType.WormFile: return "Suspicious file";
                    case ThreatType.PayloadFolder: return "Payload folder";
                    case ThreatType.StartupScr: return "Startup stager";
                    case ThreatType.BadTask: return "Fake scheduled task";
                    case ThreatType.BadRunKey: return "Startup registry entry";
                    case ThreatType.BadExclusion: return "Defender exclusion";
                    case ThreatType.DefenderOff: return "Defender disabled";
                    case ThreatType.MaliciousProcess: return "Running malware";
                    case ThreatType.KnownMalware: return "Known malware file";
                    case ThreatType.BadAutorun: return "autorun.inf dropper";
                    default: return Type.ToString();
                }
            }
        }
    }

    static class Detect
    {
        // sample hashes captured during the September 2026 sysvolume outbreak this tool was written after
        public static readonly Dictionary<string, string> KnownHashes = new Dictionary<string, string>
        {
            { "6497176D125C695A4BCED5033761D81A6AE147CC3A5D9A8E95098F480CC5F892", "sysvolume worm payload (.dat)" },
            { "4F241E2CD5DFEB4659234E896E22BA29CA771FC86FD3E385C32AE5B8B4000324", "worm installer .bat" },
            { "0665FB6B425D5E2DAE76FBF34B2789EC463E30E0E65109FBE0100E9F29F718A9", "worm launcher .vbs" },
            { "AD1380550DE3AF07F6AD626A2B579F70782499DEE065919BC223566A1D4206BE", "fake RealtekAudioService / bound.exe" },
            { "45716B91857119BFD55394DC92882504573B10F25DF8FEE7B17EE07BCBAD03A9", "invisible-name .scr stager" },
            { "63AA8DA1AEDB07D075C13F700877A7525DF5B4F434C5F24026A77365517CB225", "wsvcz miner exe" },
            { "11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5", "WinRing0x64.sys miner driver" },
            { "44E5B39BCB07F148B1596953C9230D6E1F0B9C752B5C2E1A5DC8A56E1DBD3FF4", "wlogz.dat config" }
        };

        static readonly Regex WormName = new Regex(@"^u\d{6}\.(vbs|bat|cmd|js|jse|dat|bin|dll|exe|scr|sys)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex BadPath = new Regex(@"(\\sysvolume(\\|$)|\\subdir(\\|$)|\\wsvcz(\\|$)|\\u\d{6}\.(dll|exe|scr|dat|vbs|bat|cmd|js|jse|bin|sys)|\.scr$|bound\.exe$|wormgpt)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex ScriptExt = new Regex(@"\.(vbs|js|jse|vbe|bat|cmd)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex FakeExtension = new Regex(@"\.(jpg|jpeg|png|gif|pdf|doc|docx|txt|mp3|mp4)\.(exe|scr|bat|cmd|com|pif)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // system folders that are never touched, on any drive
        public static readonly string[] SkipDirs = { "$RECYCLE.BIN", "System Volume Information", "Recycler", "Recycled", "Found.000" };

        // Windows' own hidden+system root folders, these are normal
        static readonly HashSet<string> LegitHiddenRoot = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Documents and Settings", "Recovery", "$Recycle.Bin", "System Volume Information", "Config.Msi",
            "MSOCache", "Intel", "PerfLogs", "ProgramData", "Windows", "Windows.old",
            "Program Files", "Program Files (x86)", "Users", "boot", "EFI"
        };

        public static bool NameIsWormy(string name) { return WormName.IsMatch(name); }
        public static bool PathIsBad(string p) { return !string.IsNullOrEmpty(p) && BadPath.IsMatch(p); }
        public static bool IsScriptFile(string name) { return ScriptExt.IsMatch(name); }
        public static bool HasFakeExtension(string name) { return FakeExtension.IsMatch(name); }

        public static bool IsSkipDir(string name)
        {
            foreach (string s in SkipDirs)
                if (string.Equals(s, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public static bool IsLegitHiddenRoot(string name) { return LegitHiddenRoot.Contains(name); }

        public static bool HasInvisibleChars(string s)
        {
            foreach (char c in s)
            {
                if (c < 0x20 && c != ' ') return true;
                if (c >= 0x200B && c <= 0x200F) return true;
                if (c >= 0x2060 && c <= 0x206F) return true;
            }
            return false;
        }

        public static string Sha256(string file)
        {
            try
            {
                var fi = new FileInfo(file);
                if (fi.Length > 100 * 1024 * 1024) return "";
                using (Stream s = File.OpenRead(file))
                using (SHA256 h = SHA256.Create())
                {
                    byte[] b = h.ComputeHash(s);
                    var sb = new StringBuilder(b.Length * 2);
                    foreach (byte x in b) sb.Append(x.ToString("X2"));
                    return sb.ToString();
                }
            }
            catch { return ""; }
        }

        // returns the sample label if the file is a known malware hash, otherwise null
        public static string KnownHashName(string file)
        {
            string h = Sha256(file);
            if (h.Length == 0) return null;
            string label;
            return KnownHashes.TryGetValue(h, out label) ? label : null;
        }

        public static string ResolveShortcut(string lnkFile)
        {
            try
            {
                dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
                dynamic sc = shell.CreateShortcut(lnkFile);
                string target = (string)sc.TargetPath;
                string arguments = "";
                try { arguments = (string)sc.Arguments ?? ""; } catch { }
                if (string.IsNullOrWhiteSpace(target)) return "";
                return target + (string.IsNullOrWhiteSpace(arguments) ? "" : " " + arguments);
            }
            catch { return ""; }
        }
    }

    static class Engine
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool MoveFileEx(string existingFile, string newFile, int flags);

        const int MoveFileDelayUntilReboot = 4;

        public static bool IsElevated()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        public static string RunPowerShell(string command)
        {
            try
            {
                var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command \"" + command + "\"")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(60000);
                    return (output ?? "").Trim();
                }
            }
            catch (Exception ex) { return "!ERR " + ex.Message; }
        }

        public static string PsQuote(string s) { return "'" + (s ?? "").Replace("'", "''") + "'"; }

        static void RunTool(string exe, string args)
        {
            try { Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true }).WaitForExit(10000); }
            catch { }
        }

        // delete that survives file locks, attribute games and ACLs
        public static bool DeleteFileHard(string path, Action<string> log)
        {
            for (int i = 0; i < 3; i++)
            {
                try { File.SetAttributes(path, FileAttributes.Normal); File.Delete(path); return true; }
                catch { Thread.Sleep(350); }
            }
            try
            {
                RunTool("takeown", "/f \"" + path + "\"");
                RunTool("icacls", "\"" + path + "\" /grant *S-1-5-32-544:F");
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
                return true;
            }
            catch { }
            try
            {
                if (MoveFileEx(path, null, MoveFileDelayUntilReboot))
                {
                    if (log != null) log("Scheduled for deletion at next reboot: " + path);
                    return true;
                }
            }
            catch { }
            return false;
        }

        public static void DeleteTree(string path, Action<string> log)
        {
            try
            {
                foreach (string f in Directory.GetFiles(path, "*", SearchOption.AllDirectories)) DeleteFileHard(f, log);
                foreach (string d in Directory.GetDirectories(path, "*", SearchOption.AllDirectories).OrderByDescending(x => x.Length))
                { try { Directory.Delete(d, true); } catch { } }
                try { Directory.Delete(path, true); } catch { }
            }
            catch (Exception ex) { if (log != null) log("Could not fully delete " + path + ": " + ex.Message); }
        }

        public static bool DeleteTask(string taskPath)
        {
            try
            {
                dynamic ts = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
                ts.Connect();
                int i = taskPath.LastIndexOf('\\');
                string parent = i <= 0 ? "\\" : taskPath.Substring(0, i);
                dynamic folder = ts.GetFolder(parent);
                folder.DeleteTask(taskPath.Substring(i + 1), false);
                return true;
            }
            catch { return false; }
        }

        public static void WalkTaskFolder(dynamic folder, List<Finding> found)
        {
            foreach (dynamic t in folder.GetTasks(0))
            {
                try
                {
                    string taskPath = (string)t.Path;
                    foreach (dynamic a in t.Actions)
                    {
                        string exe = "";
                        try { exe = (string)a.Execute ?? ""; } catch { }
                        if (exe.Length > 0 && Detect.PathIsBad(exe))
                        {
                            found.Add(new Finding
                            {
                                Type = ThreatType.BadTask,
                                Severity = Severity.Critical,
                                Path = taskPath + "  ->  " + exe,
                                Detail = "Scheduled task runs malware",
                                TaskPath = taskPath
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
            foreach (dynamic sub in folder.GetFolders(0)) WalkTaskFolder(sub, found);
        }
    }
}
