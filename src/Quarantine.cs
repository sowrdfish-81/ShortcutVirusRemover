using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace ShortcutVirusRemover
{
    class QuarantineEntry
    {
        public string Id;
        public string Date;
        public string Threat;
        public string OriginalPath;

        public string StoredPath { get { return Path.Combine(AppData.QuarantineDir, Id + ".qtn"); } }
    }

    // quarantined files are copied out and the original deleted; the index remembers where they came from
    static class Quarantine
    {
        static readonly object Gate = new object();
        static List<QuarantineEntry> entries;
        static bool loaded;

        static string IndexFile { get { return Path.Combine(AppData.QuarantineDir, "index.txt"); } }

        public static List<QuarantineEntry> Entries
        {
            get { lock (Gate) { Load(); return entries.ToList(); } }
        }

        static void Load()
        {
            if (loaded) return;
            entries = new List<QuarantineEntry>();
            try
            {
                if (File.Exists(IndexFile))
                {
                    foreach (string line in File.ReadAllLines(IndexFile))
                    {
                        string[] parts = line.Split('|');
                        if (parts.Length < 4) continue;
                        entries.Add(new QuarantineEntry { Id = parts[0], Date = parts[1], Threat = parts[2], OriginalPath = parts[3] });
                    }
                }
            }
            catch { }
            loaded = true;
        }

        static void Save()
        {
            try
            {
                var lines = new List<string>();
                foreach (QuarantineEntry e in entries) lines.Add(e.Id + "|" + e.Date + "|" + e.Threat + "|" + e.OriginalPath);
                File.WriteAllLines(IndexFile, lines);
            }
            catch { }
        }

        public static bool QuarantineFile(string path, string threat, Action<string> log)
        {
            if (string.IsNullOrEmpty(path) || path.StartsWith(AppData.QuarantineDir, StringComparison.OrdinalIgnoreCase)) return false;
            lock (Gate)
            {
                Load();
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    try
                    {
                        if (!File.Exists(path)) return false;
                        var e = new QuarantineEntry
                        {
                            Id = Guid.NewGuid().ToString("N").Substring(0, 12),
                            Date = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
                            Threat = threat,
                            OriginalPath = path
                        };
                        try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
                        // copy+delete, File.Move refuses to cross volumes
                        File.Copy(path, e.StoredPath, true);
                        File.Delete(path);
                        entries.Add(e);
                        Save();
                        if (log != null) log("Quarantined: " + path);
                        AppData.Settings.ThreatsRemoved++;
                        AppData.SaveSettings();
                        return true;
                    }
                    catch (Exception ex)
                    {
                        if (attempt == 2 && log != null) log("Could not quarantine " + path + ": " + ex.Message);
                        Thread.Sleep(300);
                    }
                }
                return false;
            }
        }

        public static bool Restore(QuarantineEntry entry, Action<string> log)
        {
            lock (Gate)
            {
                Load();
                try
                {
                    if (!File.Exists(entry.StoredPath))
                    {
                        if (log != null) log("Quarantined file is gone: " + entry.StoredPath);
                        return false;
                    }
                    string target = entry.OriginalPath;
                    if (File.Exists(target)) target = target + ".restored";
                    string dir = Path.GetDirectoryName(target);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    File.Copy(entry.StoredPath, target);
                    File.Delete(entry.StoredPath);
                    entries.RemoveAll(x => x.Id == entry.Id);
                    Save();
                    if (log != null) log("Restored to " + target);
                    return true;
                }
                catch (Exception ex)
                {
                    if (log != null) log("Restore failed: " + ex.Message);
                    return false;
                }
            }
        }

        public static bool DeleteForever(QuarantineEntry entry, Action<string> log)
        {
            lock (Gate)
            {
                Load();
                try
                {
                    if (File.Exists(entry.StoredPath)) File.Delete(entry.StoredPath);
                    entries.RemoveAll(x => x.Id == entry.Id);
                    Save();
                    if (log != null) log("Deleted from quarantine: " + entry.OriginalPath);
                    return true;
                }
                catch (Exception ex)
                {
                    if (log != null) log("Delete failed: " + ex.Message);
                    return false;
                }
            }
        }
    }
}
