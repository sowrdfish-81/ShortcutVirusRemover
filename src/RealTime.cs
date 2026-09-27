using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace ShortcutVirusRemover
{
    // background protection: watches for USB drives being plugged in and for files appearing in the Startup folder
    class RealTimeProtection
    {
        public volatile bool Paused;
        public int BlockedCount;

        Thread worker;
        volatile bool stopped;
        readonly HashSet<string> knownUsb = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly object driveGate = new object();
        FileSystemWatcher startupWatcher;

        public Action<string, bool> Notify = delegate { };
        public Action<string> Log = delegate { };

        public void Start()
        {
            // remember the drives that are already plugged in so we don't rescan them on every start
            try
            {
                foreach (DriveInfo d in DriveInfo.GetDrives())
                    if (d.DriveType == DriveType.Removable && d.IsReady)
                        knownUsb.Add(d.RootDirectory.FullName);
            }
            catch { }

            WatchStartup();
            worker = new Thread(Loop);
            worker.IsBackground = true;
            worker.Start();
            Log("Real-time protection started");
        }

        public void Stop()
        {
            stopped = true;
            try { if (startupWatcher != null) startupWatcher.Dispose(); } catch { }
        }

        void Loop()
        {
            while (!stopped)
            {
                try { if (!Paused && AppData.Settings.ScanUsb) CheckDrives(); }
                catch { }
                for (int i = 0; i < 30 && !stopped; i++) Thread.Sleep(100);
            }
        }

        void CheckDrives()
        {
            List<string> arrived = null;
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                if (d.DriveType != DriveType.Removable || !d.IsReady) continue;
                string root = d.RootDirectory.FullName;
                lock (driveGate)
                {
                    if (knownUsb.Contains(root)) continue;
                    knownUsb.Add(root);
                }
                if (arrived == null) arrived = new List<string>();
                arrived.Add(root);
            }
            if (arrived == null) return;
            foreach (string root in arrived)
            {
                if (stopped || Paused) return;
                Thread.Sleep(1200);   // let the shell finish mounting the volume
                ScanUsbDrive(root);
            }
        }

        void ScanUsbDrive(string root)
        {
            int blocked = 0;
            var hidden = new List<string>();
            Log("USB drive connected: " + root);

            try
            {
                // the sysvolume payload folder
                string sysvol = Path.Combine(root, "sysvolume");
                if (Directory.Exists(sysvol))
                {
                    foreach (string f in Directory.GetFiles(sysvol))
                        if (Quarantine.QuarantineFile(f, "sysvolume worm payload (USB)", Log)) blocked++;
                    try { Directory.Delete(sysvol, true); } catch { Engine.DeleteTree(sysvol, Log); }
                }

                // autorun.inf that launches something
                string autorun = Path.Combine(root, "autorun.inf");
                if (File.Exists(autorun))
                {
                    bool bad;
                    try
                    {
                        string content = File.ReadAllText(autorun);
                        FileAttributes attr = File.GetAttributes(autorun);
                        bad = (attr & FileAttributes.Hidden) != 0 || (attr & FileAttributes.System) != 0
                            || content.IndexOf("wscript", StringComparison.OrdinalIgnoreCase) >= 0
                            || content.IndexOf(".vbs", StringComparison.OrdinalIgnoreCase) >= 0
                            || content.IndexOf(".bat", StringComparison.OrdinalIgnoreCase) >= 0;
                    }
                    catch { bad = true; }
                    if (bad && Quarantine.QuarantineFile(autorun, "autorun.inf dropper (USB)", Log)) blocked++;
                }

                foreach (string e in Directory.GetFileSystemEntries(root))
                {
                    try
                    {
                        if (File.Exists(e))
                        {
                            string name = Path.GetFileName(e);
                            bool badShortcut = false;
                            if (string.Equals(Path.GetExtension(e), ".lnk", StringComparison.OrdinalIgnoreCase))
                            {
                                string target = Detect.ResolveShortcut(e);
                                badShortcut = Detect.PathIsBad(target) || (target.Length > 0 && Detect.IsScriptFile(target));
                            }
                            bool smells = badShortcut || Detect.NameIsWormy(name) || Detect.HasFakeExtension(name);
                            // only hash small files, nobody wants a 5 GB movie hashed on plug-in
                            if (!smells && new FileInfo(e).Length < 20 * 1024 * 1024 && Detect.KnownHashName(e) != null) smells = true;
                            if (smells && Quarantine.QuarantineFile(e, badShortcut ? "Virus shortcut (USB)" : "Worm file (USB)", Log)) blocked++;
                        }
                        else
                        {
                            string name = Path.GetFileName(e);
                            if (Detect.IsSkipDir(name) || name.Equals("sysvolume", StringComparison.OrdinalIgnoreCase)) continue;
                            FileAttributes attr = File.GetAttributes(e);
                            if ((attr & FileAttributes.Hidden) != 0 && (attr & FileAttributes.System) != 0 && !Detect.IsLegitHiddenRoot(name))
                                hidden.Add(name);
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) { Log("USB check failed on " + root + ": " + ex.Message); }

            BlockedCount += blocked;
            if (blocked > 0)
                Notify(blocked + " threat(s) blocked on " + root + (hidden.Count > 0 ? ". " + hidden.Count + " hidden folder(s) left to review, run a scan." : ""), true);
            else if (hidden.Count > 0)
                Notify(hidden.Count + " hidden folder(s) found on " + root + ", run a scan to review them.", true);
            else
                Notify("USB drive " + root + " is clean.", false);
        }

        void WatchStartup()
        {
            try
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Windows\Start Menu\Programs\Startup");
                if (!Directory.Exists(dir)) return;
                startupWatcher = new FileSystemWatcher(dir);
                startupWatcher.Created += OnStartupDrop;
                startupWatcher.EnableRaisingEvents = true;
            }
            catch { }
        }

        void OnStartupDrop(object sender, FileSystemEventArgs e)
        {
            try
            {
                string name = Path.GetFileName(e.FullPath);
                bool bad = string.Equals(Path.GetExtension(name), ".scr", StringComparison.OrdinalIgnoreCase) || Detect.NameIsWormy(name);
                if (!bad) return;
                Thread.Sleep(500);   // let the writer finish first
                if (Quarantine.QuarantineFile(e.FullPath, "Startup stager (real-time)", Log))
                {
                    BlockedCount++;
                    Notify("Blocked a Startup folder infection attempt: " + name, true);
                }
            }
            catch { }
        }
    }
}
