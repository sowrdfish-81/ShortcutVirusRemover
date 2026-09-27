using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace ShortcutVirusRemover
{
    class FixResult { public int Fixed; public int Failed; }

    static class Fixer
    {
        // tasks, HKLM values, Defender settings and system folders all need admin; the rest can be fixed as user
        public static bool NeedsElevation(List<Finding> items)
        {
            return items.Any(f =>
                f.Type == ThreatType.BadTask
                || f.Type == ThreatType.BadExclusion
                || f.Type == ThreatType.DefenderOff
                || f.Type == ThreatType.PayloadFolder
                || f.Type == ThreatType.MaliciousProcess
                || (f.Type == ThreatType.BadRunKey && f.RegPath.StartsWith("HKLM")));
        }

        public static FixResult Fix(List<Finding> items, Action<string> log)
        {
            var result = new FixResult();
            log("== Fix started at " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " ==");
            bool explorerKilled = false;

            // kill processes first so nothing holds the files open
            foreach (Finding f in items.Where(x => x.Type == ThreatType.MaliciousProcess))
            {
                try
                {
                    Process p = Process.GetProcessById(f.Pid);
                    if (string.Equals(p.ProcessName, "explorer", StringComparison.OrdinalIgnoreCase)) explorerKilled = true;
                    p.Kill();
                    p.WaitForExit(5000);
                    log("Killed process " + f.Path + " (" + f.Detail + ")");
                    result.Fixed++;
                }
                catch (Exception ex) { log("Could not kill PID " + f.Pid + ": " + ex.Message); result.Failed++; }
            }

            foreach (Finding f in items.Where(x => x.Type == ThreatType.BadTask))
            {
                if (Engine.DeleteTask(f.TaskPath)) { log("Removed scheduled task " + f.TaskPath); result.Fixed++; }
                else { log("Could not remove scheduled task " + f.TaskPath); result.Failed++; }
            }

            foreach (Finding f in items.Where(x => x.Type == ThreatType.BadRunKey))
            {
                try
                {
                    RegistryHive hive = f.RegPath.StartsWith("HKCU") ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
                    string sub = f.RegPath.Substring(f.RegPath.IndexOf('\\') + 1);
                    BackupRunValue(hive, sub, f.RegName, log);
                    using (RegistryKey key = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(sub, true))
                    {
                        if (key != null)
                        {
                            key.DeleteValue(f.RegName, false);
                            log("Removed registry value: " + f.Path);
                            result.Fixed++;
                        }
                        else result.Failed++;
                    }
                }
                catch (Exception ex) { log("Registry fix failed for " + f.Path + ": " + ex.Message); result.Failed++; }
            }

            foreach (Finding f in items.Where(x => x.Type == ThreatType.BadExclusion))
            {
                string r = Engine.RunPowerShell("Remove-MpPreference -ExclusionPath " + Engine.PsQuote(f.Exclusion));
                if (r.Length == 0 || r.IndexOf("error", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    log("Removed Defender exclusion: " + f.Exclusion);
                    result.Fixed++;
                }
                else { log("Could not remove exclusion: " + r); result.Failed++; }
            }

            foreach (Finding f in items.Where(x => x.Type == ThreatType.DefenderOff))
            {
                Engine.RunPowerShell("Set-MpPreference -DisableRealtimeMonitoring $false");
                log("Turned Windows Defender real-time protection back on");
                result.Fixed++;
            }

            // worm folders: quarantine what is inside, then remove the empty shell
            foreach (Finding f in items.Where(x => x.Type == ThreatType.WormFolder || x.Type == ThreatType.PayloadFolder))
            {
                if (!Directory.Exists(f.Path)) continue;
                try
                {
                    foreach (string file in Directory.GetFiles(f.Path))
                        if (!Quarantine.QuarantineFile(file, "Worm payload from " + f.Path, log))
                            Engine.DeleteFileHard(file, log);
                    Engine.DeleteTree(f.Path, log);
                    log("Removed worm folder " + f.Path);
                    result.Fixed++;
                }
                catch (Exception ex) { log("Folder fix failed for " + f.Path + ": " + ex.Message); result.Failed++; }
            }

            foreach (Finding f in items.Where(x => x.Type == ThreatType.VirusShortcut || x.Type == ThreatType.StartupScr ||
                                                   x.Type == ThreatType.WormFile || x.Type == ThreatType.KnownMalware ||
                                                   x.Type == ThreatType.BadAutorun))
            {
                if (Directory.Exists(f.Path)) { Engine.DeleteTree(f.Path, log); result.Fixed++; continue; }
                if (!File.Exists(f.Path)) continue;   // real-time protection may have caught it already
                if (Quarantine.QuarantineFile(f.Path, f.TypeName, log) || Engine.DeleteFileHard(f.Path, log)) result.Fixed++;
                else { log("Could not remove " + f.Path); result.Failed++; }
            }

            // hidden folders are the user's own files, never delete them, just unhide
            foreach (Finding f in items.Where(x => x.Type == ThreatType.HiddenFolder))
            {
                try
                {
                    FileAttributes a = File.GetAttributes(f.Path);
                    File.SetAttributes(f.Path, a & ~(FileAttributes.Hidden | FileAttributes.System));
                    log("Unhid " + f.Path);
                    result.Fixed++;
                }
                catch (Exception ex) { log("Could not unhide " + f.Path + ": " + ex.Message); result.Failed++; }
            }

            if (explorerKilled)
            {
                try { Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true }); log("Restarted Explorer"); } catch { }
            }

            log("== Fix finished: " + result.Fixed + " fixed, " + result.Failed + " failed ==");
            return result;
        }

        // keep a plain-text copy of registry values before they are removed, so mistakes can be undone by hand
        static void BackupRunValue(RegistryHive hive, string subKey, string valueName, Action<string> log)
        {
            try
            {
                using (RegistryKey key = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(subKey))
                {
                    if (key == null) return;
                    object data = key.GetValue(valueName);
                    if (data == null) return;
                    string line = DateTime.Now.ToString("s") + " | " + hive + "\\" + subKey + " | " + valueName + " | " + data;
                    File.AppendAllText(Path.Combine(AppData.Root, "registry-backup.txt"), line + Environment.NewLine);
                    log("Backed up the registry value before removing it");
                }
            }
            catch { }
        }

        // utility used by the Settings page: strip hidden+system from the top folders of a drive
        public static int UnhideDriveFolders(string root, Action<string> log)
        {
            int n = 0;
            try
            {
                foreach (string d in Directory.GetDirectories(root))
                {
                    string name = Path.GetFileName(d);
                    if (Detect.IsSkipDir(name)) continue;
                    try
                    {
                        FileAttributes a = File.GetAttributes(d);
                        if ((a & FileAttributes.Hidden) != 0 || (a & FileAttributes.System) != 0)
                        {
                            File.SetAttributes(d, a & ~(FileAttributes.Hidden | FileAttributes.System));
                            n++;
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) { if (log != null) log("Unhide failed: " + ex.Message); }
            if (log != null) log("Unhid " + n + " folder(s) on " + root);
            return n;
        }
    }
}
