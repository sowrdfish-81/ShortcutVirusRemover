using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace ShortcutVirusRemover
{
    enum ScanKind { Quick, Full, Folder }

    class ScanOptions
    {
        public ScanKind Kind;
        public string CustomFolder;
        public bool Elevated;
    }

    class ScanContext
    {
        public readonly object Sync = new object();
        public readonly List<Finding> Found = new List<Finding>();
        public Func<bool> Cancelled = delegate { return false; };
        public Action<string> Status = delegate { };
        public Action<string> Log = delegate { };
        int filesChecked;

        public void Add(Finding f)
        {
            if (f == null) return;
            lock (Sync)
            {
                if (AppData.IsWhitelisted(f.Path)) return;
                for (int i = 0; i < Found.Count; i++)
                    if (string.Equals(Found[i].Path, f.Path, StringComparison.OrdinalIgnoreCase)) return;
                Found.Add(f);
            }
        }

        public void CountFile() { lock (Sync) filesChecked++; }
        public int FileCount { get { lock (Sync) return filesChecked; } }
    }

    static class ScanEngine
    {
        public static void RunScan(ScanOptions o, ScanContext ctx)
        {
            ctx.Log("== Scan started (" + o.Kind + ") at " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " ==");
            try
            {
                if (o.Kind == ScanKind.Folder) ScanTree(o.CustomFolder, ctx);
                else
                {
                    ScanDriveRoots(o, ctx);
                    ScanStartupAndTemp(ctx);
                    ScanRegistry(ctx);
                    ScanProcesses(ctx);
                    if (o.Kind == ScanKind.Full)
                    {
                        ScanSystemFolders(ctx);
                        ScanTasks(ctx);
                        ScanDefender(o, ctx);
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { ctx.Log("[!] Scan error: " + ex.Message); }
            ctx.Log("== Scan finished: " + ctx.Found.Count + " finding(s) after " + ctx.FileCount + " items ==");
        }

        static void CheckCancel(ScanContext ctx)
        {
            if (ctx.Cancelled()) throw new OperationCanceledException();
        }

        static void HashCheck(string file, ScanContext ctx)
        {
            string label = Detect.KnownHashName(file);
            if (label != null)
                ctx.Add(new Finding
                {
                    Type = ThreatType.KnownMalware,
                    Severity = Severity.Critical,
                    Path = file,
                    Detail = "SHA256 matches known sample: " + label
                });
        }

        static void ScanDriveRoots(ScanOptions o, ScanContext ctx)
        {
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                CheckCancel(ctx);
                try { if (!d.IsReady) continue; } catch { continue; }
                if (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable && d.DriveType != DriveType.Ram) continue;
                string root = d.RootDirectory.FullName;
                ctx.Status("Checking drive " + root);

                string sysvol = Path.Combine(root, "sysvolume");
                if (Directory.Exists(sysvol))
                {
                    string[] inner = new string[0];
                    try { inner = Directory.GetFiles(sysvol); } catch { }
                    ctx.Add(new Finding
                    {
                        Type = ThreatType.WormFolder,
                        Severity = Severity.Critical,
                        IsDirectory = true,
                        Path = sysvol,
                        Detail = inner.Length == 0
                            ? "Worm folder on the drive root"
                            : "Worm folder, contains: " + string.Join(", ", inner.Select(Path.GetFileName))
                    });
                    foreach (string f in inner) HashCheck(f, ctx);
                }

                CheckAutorun(root, ctx);

                string[] entries = new string[0];
                try { entries = Directory.GetFileSystemEntries(root); } catch { }
                foreach (string e in entries)
                {
                    CheckCancel(ctx);
                    ctx.CountFile();
                    try
                    {
                        if (File.Exists(e)) CheckRootFile(e, ctx);
                        else
                        {
                            string name = Path.GetFileName(e);
                            if (Detect.IsSkipDir(name)) continue;
                            FileAttributes attr = File.GetAttributes(e);
                            if ((attr & FileAttributes.Hidden) != 0 && (attr & FileAttributes.System) != 0 && !Detect.IsLegitHiddenRoot(name))
                                ctx.Add(new Finding
                                {
                                    Type = ThreatType.HiddenFolder,
                                    Severity = Severity.Suspicious,
                                    IsDirectory = true,
                                    Path = e,
                                    Detail = "Folder is hidden with the system attribute (typical worm behaviour)"
                                });
                        }
                    }
                    catch { }
                }

                // pendrives are small, walk them fully on a full scan
                if (o.Kind == ScanKind.Full && d.DriveType == DriveType.Removable) ScanTree(root, ctx);
            }
        }

        static void CheckRootFile(string file, ScanContext ctx)
        {
            string name = Path.GetFileName(file);
            if (string.Equals(Path.GetExtension(file), ".lnk", StringComparison.OrdinalIgnoreCase))
            {
                string target = Detect.ResolveShortcut(file);
                if (Detect.PathIsBad(target) || (target.Length > 0 && Detect.IsScriptFile(target)))
                    ctx.Add(new Finding
                    {
                        Type = ThreatType.VirusShortcut,
                        Severity = Severity.Critical,
                        Path = file,
                        Detail = "Shortcut launches: " + (target.Length == 0 ? "(unreadable target)" : target)
                    });
            }
            else if (Detect.NameIsWormy(name))
                ctx.Add(new Finding { Type = ThreatType.WormFile, Severity = Severity.Critical, Path = file, Detail = "Worm dropper pattern (uXXXXXX.ext) at drive root" });
            else if (Detect.HasFakeExtension(name))
                ctx.Add(new Finding { Type = ThreatType.WormFile, Severity = Severity.Critical, Path = file, Detail = "Fake double extension, e.g. photo.jpg.exe" });
            else if (Detect.HasInvisibleChars(name))
                ctx.Add(new Finding { Type = ThreatType.WormFile, Severity = Severity.Critical, Path = file, Detail = "File name contains invisible characters" });
        }

        static void CheckAutorun(string root, ScanContext ctx)
        {
            string path = Path.Combine(root, "autorun.inf");
            try
            {
                if (!File.Exists(path)) return;
                ctx.CountFile();
                string content = File.ReadAllText(path);
                FileAttributes attr = File.GetAttributes(path);
                bool hidden = (attr & FileAttributes.Hidden) != 0 || (attr & FileAttributes.System) != 0;
                bool scripty = content.IndexOf("wscript", StringComparison.OrdinalIgnoreCase) >= 0
                    || content.IndexOf(".vbs", StringComparison.OrdinalIgnoreCase) >= 0
                    || content.IndexOf(".bat", StringComparison.OrdinalIgnoreCase) >= 0
                    || content.IndexOf(".cmd", StringComparison.OrdinalIgnoreCase) >= 0;
                if (hidden || scripty)
                    ctx.Add(new Finding
                    {
                        Type = ThreatType.BadAutorun,
                        Severity = Severity.Critical,
                        Path = path,
                        Detail = hidden ? "Hidden autorun.inf (worm dropper)" : "autorun.inf launches a script"
                    });
            }
            catch { }
        }

        static void ScanStartupAndTemp(ScanContext ctx)
        {
            ctx.Status("Checking Startup folders and TEMP");
            string[] startupFolders =
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\StartUp")
            };
            foreach (string dir in startupFolders)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (string f in Directory.GetFiles(dir))
                {
                    CheckCancel(ctx);
                    ctx.CountFile();
                    string name = Path.GetFileName(f);
                    if (string.Equals(Path.GetExtension(f), ".scr", StringComparison.OrdinalIgnoreCase))
                        ctx.Add(new Finding
                        {
                            Type = ThreatType.StartupScr,
                            Severity = Severity.Critical,
                            Path = f,
                            Detail = (Detect.HasInvisibleChars(name) ? "Invisible name, " : "") + "screensaver files in Startup are a classic stager"
                        });
                    else if (Detect.NameIsWormy(name))
                        ctx.Add(new Finding { Type = ThreatType.WormFile, Severity = Severity.Critical, Path = f, Detail = "Worm dropper in Startup" });
                    else if (Detect.HasFakeExtension(name))
                        ctx.Add(new Finding { Type = ThreatType.WormFile, Severity = Severity.Critical, Path = f, Detail = "Fake double extension in Startup" });
                }
            }

            try
            {
                string tmp = Path.GetTempPath();
                foreach (string f in Directory.GetFiles(tmp))
                {
                    CheckCancel(ctx);
                    ctx.CountFile();
                    string name = Path.GetFileName(f);
                    if (Detect.NameIsWormy(name)
                        || Detect.HasFakeExtension(name)
                        || string.Equals(name, "bound.exe", StringComparison.OrdinalIgnoreCase)
                        || (string.Equals(Path.GetExtension(f), ".scr", StringComparison.OrdinalIgnoreCase) && Detect.HasInvisibleChars(name)))
                        ctx.Add(new Finding { Type = ThreatType.WormFile, Severity = Severity.Critical, Path = f, Detail = "Worm file in the TEMP folder" });
                }
            }
            catch { }
        }

        static readonly string[] RunKeys =
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        };

        static void ScanRegistry(ScanContext ctx)
        {
            ctx.Status("Checking autorun registry keys");
            foreach (string keyPath in RunKeys)
            {
                foreach (RegistryHive hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
                {
                    CheckCancel(ctx);
                    try
                    {
                        using (RegistryKey key = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(keyPath))
                        {
                            if (key == null) continue;
                            foreach (string valueName in key.GetValueNames())
                            {
                                string data = Convert.ToString(key.GetValue(valueName) ?? "");
                                if (Detect.PathIsBad(data) || Detect.HasInvisibleChars(valueName))
                                {
                                    string hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM";
                                    ctx.Add(new Finding
                                    {
                                        Type = ThreatType.BadRunKey,
                                        Severity = Severity.Critical,
                                        Path = hiveName + "\\" + keyPath + "  ->  " + valueName,
                                        Detail = data,
                                        RegPath = hiveName + "\\" + keyPath,
                                        RegName = valueName
                                    });
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        static void ScanProcesses(ScanContext ctx)
        {
            ctx.Status("Checking running processes");
            foreach (Process p in Process.GetProcesses())
            {
                CheckCancel(ctx);
                string image = null;
                try { image = p.MainModule != null ? p.MainModule.FileName : null; } catch { }
                if (!string.IsNullOrEmpty(image) && Detect.PathIsBad(image))
                {
                    ctx.Add(new Finding
                    {
                        Type = ThreatType.MaliciousProcess,
                        Severity = Severity.Critical,
                        Path = image,
                        Detail = "Running now, PID " + p.Id,
                        Pid = p.Id
                    });
                    continue;
                }
                try
                {
                    foreach (ProcessModule m in p.Modules)
                    {
                        if (Detect.NameIsWormy(m.ModuleName ?? ""))
                        {
                            ctx.Add(new Finding
                            {
                                Type = ThreatType.MaliciousProcess,
                                Severity = Severity.Critical,
                                Path = image ?? p.ProcessName,
                                Detail = "Loaded worm module " + m.ModuleName + " (PID " + p.Id + ")",
                                Pid = p.Id
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }

        static void ScanSystemFolders(ScanContext ctx)
        {
            string[] sysDirs =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
            };
            foreach (string sysDir in sysDirs)
            {
                if (string.IsNullOrEmpty(sysDir) || !Directory.Exists(sysDir)) continue;
                foreach (string bad in new[] { "SubDir", "wsvcz" })
                {
                    string p = Path.Combine(sysDir, bad);
                    if (Directory.Exists(p))
                        ctx.Add(new Finding
                        {
                            Type = ThreatType.PayloadFolder,
                            Severity = Severity.Critical,
                            IsDirectory = true,
                            Path = p,
                            Detail = "Fake system folder (RAT / miner base)"
                        });
                }
                ctx.Status("Checking " + sysDir);
                try
                {
                    foreach (string f in Directory.GetFiles(sysDir))
                    {
                        CheckCancel(ctx);
                        ctx.CountFile();
                        string name = Path.GetFileName(f);
                        if (Detect.NameIsWormy(name))
                            ctx.Add(new Finding { Type = ThreatType.WormFile, Severity = Severity.Critical, Path = f, Detail = "Worm-pattern file inside " + sysDir });
                        else HashCheck(f, ctx);
                    }
                    foreach (string sub in Directory.GetDirectories(sysDir))
                    {
                        try
                        {
                            foreach (string f in Directory.GetFiles(sub))
                            {
                                CheckCancel(ctx);
                                ctx.CountFile();
                                if (Detect.NameIsWormy(Path.GetFileName(f)))
                                {
                                    ctx.Add(new Finding
                                    {
                                        Type = ThreatType.PayloadFolder,
                                        Severity = Severity.Critical,
                                        IsDirectory = true,
                                        Path = sub,
                                        Detail = "Worm files inside: " + Path.GetFileName(f)
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            try
            {
                string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                foreach (string f in Directory.GetFiles(winDir))
                {
                    CheckCancel(ctx);
                    ctx.CountFile();
                    if (Detect.NameIsWormy(Path.GetFileName(f)))
                        ctx.Add(new Finding { Type = ThreatType.WormFile, Severity = Severity.Critical, Path = f, Detail = "Worm-pattern file in the Windows folder" });
                }
            }
            catch { }
        }

        static void ScanTasks(ScanContext ctx)
        {
            ctx.Status("Checking scheduled tasks");
            try
            {
                dynamic ts = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
                ts.Connect();
                var found = new List<Finding>();
                Engine.WalkTaskFolder(ts.GetFolder("\\"), found);
                foreach (Finding f in found) ctx.Add(f);
            }
            catch (Exception ex) { ctx.Log("[!] Scheduled task check skipped: " + ex.Message); }
        }

        static void ScanDefender(ScanOptions o, ScanContext ctx)
        {
            ctx.Status("Checking Windows Defender");
            string rtp = Engine.RunPowerShell("(Get-MpComputerStatus).RealTimeProtectionEnabled");
            if (rtp.IndexOf("false", StringComparison.OrdinalIgnoreCase) >= 0)
                ctx.Add(new Finding
                {
                    Type = ThreatType.DefenderOff,
                    Severity = Severity.Critical,
                    Path = "Windows Defender real-time protection",
                    Detail = "The worm switches this off. Fix turns it back on."
                });

            if (!o.Elevated) return;
            string exclusions = Engine.RunPowerShell("(Get-MpPreference).ExclusionPath");
            if (exclusions.StartsWith("!ERR") || exclusions.IndexOf("administrator", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                ctx.Log("[!] Could not read Defender exclusions: " + exclusions);
                return;
            }
            foreach (string raw in exclusions.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("!ERR")) continue;
                bool wholeDrive = Regex.IsMatch(line, @"^[A-Za-z]:\\$");
                bool bad = wholeDrive
                    || line.IndexOf("sysvolume", StringComparison.OrdinalIgnoreCase) >= 0
                    || line.IndexOf("\\SubDir", StringComparison.OrdinalIgnoreCase) >= 0
                    || line.IndexOf("\\wsvcz", StringComparison.OrdinalIgnoreCase) >= 0
                    || line.EndsWith("\\System32", StringComparison.OrdinalIgnoreCase)
                    || line.EndsWith(".scr", StringComparison.OrdinalIgnoreCase)
                    || line.IndexOf("bound.exe", StringComparison.OrdinalIgnoreCase) >= 0
                    || line.IndexOf("wormgpt", StringComparison.OrdinalIgnoreCase) >= 0;
                if (bad)
                    ctx.Add(new Finding
                    {
                        Type = ThreatType.BadExclusion,
                        Severity = Severity.Critical,
                        Path = line,
                        Detail = wholeDrive ? "A whole drive is excluded from scanning, that is not normal" : "Exclusion added by malware",
                        Exclusion = line
                    });
            }
        }

        static void ScanTree(string root, ScanContext ctx)
        {
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) return;
            ctx.Status("Scanning " + root);
            CheckAutorun(root, ctx);
            ScanTreeDir(root, ctx);
        }

        static void ScanTreeDir(string dir, ScanContext ctx)
        {
            CheckCancel(ctx);
            string[] files = new string[0];
            try { files = Directory.GetFiles(dir); } catch { return; }
            foreach (string f in files)
            {
                CheckCancel(ctx);
                ctx.CountFile();
                CheckTreeFile(f, ctx);
            }
            string[] subDirs = new string[0];
            try { subDirs = Directory.GetDirectories(dir); } catch { }
            foreach (string sub in subDirs)
            {
                string name = Path.GetFileName(sub);
                if (Detect.IsSkipDir(name)) continue;
                try
                {
                    FileAttributes attr = File.GetAttributes(sub);
                    if ((attr & FileAttributes.Hidden) != 0 && (attr & FileAttributes.System) != 0 && !Detect.IsLegitHiddenRoot(name))
                        ctx.Add(new Finding
                        {
                            Type = ThreatType.HiddenFolder,
                            Severity = Severity.Suspicious,
                            IsDirectory = true,
                            Path = sub,
                            Detail = "Folder is hidden with the system attribute"
                        });
                }
                catch { }
                ScanTreeDir(sub, ctx);
            }
        }

        static void CheckTreeFile(string file, ScanContext ctx)
        {
            string name = Path.GetFileName(file);
            if (string.Equals(Path.GetExtension(file), ".lnk", StringComparison.OrdinalIgnoreCase))
            {
                string target = Detect.ResolveShortcut(file);
                if (Detect.PathIsBad(target) || (target.Length > 0 && Detect.IsScriptFile(target)))
                    ctx.Add(new Finding
                    {
                        Type = ThreatType.VirusShortcut,
                        Severity = Severity.Critical,
                        Path = file,
                        Detail = "Shortcut launches: " + target
                    });
                return;
            }

            bool wormy = Detect.NameIsWormy(name);
            bool fake = Detect.HasFakeExtension(name);
            bool invisible = Detect.HasInvisibleChars(name);
            bool scr = string.Equals(Path.GetExtension(file), ".scr", StringComparison.OrdinalIgnoreCase);
            if (wormy || fake || invisible || scr)
            {
                ctx.Add(new Finding
                {
                    Type = ThreatType.WormFile,
                    Severity = Severity.Critical,
                    Path = file,
                    Detail = wormy ? "Worm dropper pattern"
                        : fake ? "Fake double extension"
                        : invisible ? "Invisible characters in the name"
                        : "Screensaver file"
                });
                HashCheck(file, ctx);
            }
        }
    }
}
