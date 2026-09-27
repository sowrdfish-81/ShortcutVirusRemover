using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ShortcutVirusRemover
{
    class MainForm : Form
    {
        Panel sidebar;
        NavButton navHome, navThreats, navQuarantine, navSettings;
        Label lblAdmin;

        Panel pageHome, pageThreats, pageQuarantine, pageSettings;

        // home page controls
        ShieldView shield;
        Label lblState, lblStateDetail, lblStats;
        RoundedButton btnQuick, btnFull, btnFolder;
        MarqueeBar progress;
        Label lblScanStatus, lblScanCount;
        RoundedButton btnCancelScan;
        ToggleSwitch toggleRealtime;

        // threats page
        ListView listThreats;
        Label lblThreatSummary;
        RoundedButton btnFix, btnIgnore, btnOpenReports;

        // quarantine page
        ListView listQuarantine;

        // settings page
        ToggleSwitch toggleUsb, toggleStartWith;
        ListBox listWhitelist;
        ComboBox comboUnhide;
        Label lblAbout;

        // state
        List<Finding> currentFindings = new List<Finding>();
        volatile bool scanning;
        volatile bool cancelRequested;
        ScanContext activeCtx;
        ScanOptions lastOptions = new ScanOptions { Kind = ScanKind.Quick };
        RealTimeProtection protection;
        NotifyIcon tray;
        Timer uiTimer;
        bool reallyExit;
        bool trayHintShown;

        public MainForm()
        {
            Text = "Shortcut Virus Remover";
            ClientSize = new Size(1040, 640);
            MinimumSize = new Size(960, 580);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Theme.Window;
            Font = Theme.Body;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { Icon = SystemIcons.Shield; }

            uiTimer = new Timer { Interval = 400 };
            uiTimer.Tick += delegate
            {
                if (scanning && activeCtx != null) lblScanCount.Text = activeCtx.FileCount.ToString("N0") + " items checked";
            };

            BuildHomePage();
            BuildThreatsPage();
            BuildQuarantinePage();
            BuildSettingsPage();
            BuildSidebar();
            ShowPage(pageHome);

            SetupTray();
            StartRealtime();
            uiTimer.Start();

            Load += delegate
            {
                UpdateHomeStatus();
                // run a quick scan on open, a full one when we already have admin rights
                BeginInvoke((Action)delegate { RunScan(Engine.IsElevated() ? ScanKind.Full : ScanKind.Quick); });
            };
            FormClosing += OnFormClosing;

            AppData.Log("App started v" + Program.AppVersion + ", admin=" + Engine.IsElevated());
        }

        // ---------- sidebar ----------

        void BuildSidebar()
        {
            sidebar = new Panel { Dock = DockStyle.Left, Width = 200, BackColor = Theme.Sidebar };

            var logo = new PictureBox
            {
                Image = Theme.MakeShield(30, Theme.Accent, true),
                Size = new Size(30, 30),
                Location = new Point(16, 17),
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Theme.Sidebar
            };
            var lblName = new Label
            {
                Text = "Shortcut Virus\nRemover",
                Font = new Font("Segoe UI Semibold", 10F),
                ForeColor = Theme.Text,
                Location = new Point(54, 12),
                Size = new Size(140, 40),
                BackColor = Theme.Sidebar
            };

            navHome = new NavButton("Home") { Location = new Point(10, 84) };
            navThreats = new NavButton("Scan Results") { Location = new Point(10, 126) };
            navQuarantine = new NavButton("Quarantine") { Location = new Point(10, 168) };
            navSettings = new NavButton("Settings") { Location = new Point(10, 210) };
            navHome.Click += delegate { ShowPage(pageHome); };
            navThreats.Click += delegate { ShowPage(pageThreats); };
            navQuarantine.Click += delegate { RefreshQuarantineList(); ShowPage(pageQuarantine); };
            navSettings.Click += delegate { RefreshSettingsUi(); ShowPage(pageSettings); };

            var bottom = new Panel { Dock = DockStyle.Bottom, Height = 92, BackColor = Theme.Sidebar };
            lblAdmin = new Label { Font = Theme.Small, ForeColor = Theme.Warn, Location = new Point(18, 10), AutoSize = true, BackColor = Theme.Sidebar, Text = "Standard user" };
            var btnExit = new RoundedButton("Exit", Theme.Neutral) { Location = new Point(16, 40), Size = new Size(168, 32) };
            btnExit.Click += delegate { reallyExit = true; Close(); };
            bottom.Controls.Add(lblAdmin);
            bottom.Controls.Add(btnExit);

            sidebar.Controls.Add(logo);
            sidebar.Controls.Add(lblName);
            sidebar.Controls.Add(navHome);
            sidebar.Controls.Add(navThreats);
            sidebar.Controls.Add(navQuarantine);
            sidebar.Controls.Add(navSettings);
            sidebar.Controls.Add(bottom);
            Controls.Add(sidebar);

            bool admin = Engine.IsElevated();
            lblAdmin.Text = admin ? "Administrator" : "Standard user";
            lblAdmin.ForeColor = admin ? Theme.Safe : Theme.Warn;
        }

        void ShowPage(Panel page)
        {
            pageHome.Visible = page == pageHome;
            pageThreats.Visible = page == pageThreats;
            pageQuarantine.Visible = page == pageQuarantine;
            pageSettings.Visible = page == pageSettings;
            navHome.Selected = page == pageHome;
            navThreats.Selected = page == pageThreats;
            navQuarantine.Selected = page == pageQuarantine;
            navSettings.Selected = page == pageSettings;
        }

        // ---------- home ----------

        void BuildHomePage()
        {
            pageHome = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Window };

            var statusCard = new Card { Location = new Point(24, 24), Size = new Size(792, 150), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            shield = new ShieldView { Location = new Point(28, 33), Size = new Size(84, 84), BackColor = Theme.Card };
            shield.Set(Theme.Safe, true);
            lblState = new Label { Text = "Checking your PC...", Font = new Font("Segoe UI Semibold", 15.5F), ForeColor = Theme.Text, Location = new Point(134, 40), AutoSize = true, BackColor = Theme.Card };
            lblStateDetail = new Label { Text = "Starting up", Font = Theme.Body, ForeColor = Theme.Dim, Location = new Point(138, 78), AutoSize = true, BackColor = Theme.Card };
            statusCard.Controls.Add(shield);
            statusCard.Controls.Add(lblState);
            statusCard.Controls.Add(lblStateDetail);

            var scanCard = new Card { Location = new Point(24, 190), Size = new Size(792, 150), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            var lblScanTitle = new Label { Text = "Scan", Font = Theme.H2, ForeColor = Theme.Text, Location = new Point(20, 14), AutoSize = true, BackColor = Theme.Card };
            btnQuick = new RoundedButton("Quick Scan", Theme.Accent) { Location = new Point(20, 52), Size = new Size(150, 40) };
            btnFull = new RoundedButton("Full Scan", Theme.FromHex("3A6FD8")) { Location = new Point(182, 52), Size = new Size(150, 40) };
            btnFolder = new RoundedButton("Scan a Folder", Theme.Neutral) { Location = new Point(344, 52), Size = new Size(150, 40) };
            var lblScanDesc = new Label
            {
                Text = "Quick Scan checks drive roots, Startup, registry and running processes.\r\nFull Scan also checks system folders, scheduled tasks and Defender settings.",
                Font = Theme.Small, ForeColor = Theme.Dim, Location = new Point(20, 104), AutoSize = true, BackColor = Theme.Card
            };
            progress = new MarqueeBar { Location = new Point(20, 56), Size = new Size(752, 10), Visible = false, BackColor = Theme.Card };
            lblScanStatus = new Label { Text = "", Font = Theme.Body, ForeColor = Theme.Dim, Location = new Point(20, 78), AutoSize = true, Visible = false, BackColor = Theme.Card };
            lblScanCount = new Label { Text = "", Font = Theme.Body, ForeColor = Theme.Dim, Location = new Point(20, 106), AutoSize = true, Visible = false, BackColor = Theme.Card };
            btnCancelScan = new RoundedButton("Cancel", Theme.Neutral) { Location = new Point(672, 14), Size = new Size(100, 30), Visible = false };
            btnCancelScan.Click += delegate
            {
                cancelRequested = true;
                btnCancelScan.Enabled = false;
                lblScanStatus.Text = "Cancelling...";
            };
            scanCard.Controls.Add(lblScanTitle);
            scanCard.Controls.Add(btnQuick);
            scanCard.Controls.Add(btnFull);
            scanCard.Controls.Add(btnFolder);
            scanCard.Controls.Add(lblScanDesc);
            scanCard.Controls.Add(progress);
            scanCard.Controls.Add(lblScanStatus);
            scanCard.Controls.Add(lblScanCount);
            scanCard.Controls.Add(btnCancelScan);

            btnQuick.Click += delegate { RunScan(ScanKind.Quick); };
            btnFull.Click += delegate { RunScan(ScanKind.Full); };
            btnFolder.Click += delegate
            {
                using (var dlg = new FolderBrowserDialog { Description = "Choose a folder or drive to scan" })
                    if (dlg.ShowDialog(this) == DialogResult.OK) RunScan(ScanKind.Folder, dlg.SelectedPath);
            };

            var protectCard = new Card { Location = new Point(24, 356), Size = new Size(792, 104), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            var lblProtect = new Label { Text = "Real-time protection", Font = Theme.H2, ForeColor = Theme.Text, Location = new Point(20, 16), AutoSize = true, BackColor = Theme.Card };
            var lblProtectDesc = new Label
            {
                Text = "Watches USB drives and the Startup folder. Threats found there are quarantined automatically.",
                Font = Theme.Small, ForeColor = Theme.Dim, Location = new Point(20, 44), AutoSize = true, BackColor = Theme.Card
            };
            lblStats = new Label { Text = "", Font = Theme.Small, ForeColor = Theme.Dim, Location = new Point(20, 68), AutoSize = true, BackColor = Theme.Card };
            toggleRealtime = new ToggleSwitch { Location = new Point(720, 40), Checked = AppData.Settings.RealTime, BackColor = Theme.Card };
            toggleRealtime.CheckedChanged += delegate
            {
                AppData.Settings.RealTime = toggleRealtime.Checked;
                AppData.SaveSettings();
                if (protection != null) protection.Paused = !toggleRealtime.Checked;
                AppData.Log("Real-time protection " + (toggleRealtime.Checked ? "enabled" : "paused"));
            };
            protectCard.Controls.Add(lblProtect);
            protectCard.Controls.Add(lblProtectDesc);
            protectCard.Controls.Add(lblStats);
            protectCard.Controls.Add(toggleRealtime);

            pageHome.Controls.Add(statusCard);
            pageHome.Controls.Add(scanCard);
            pageHome.Controls.Add(protectCard);
            Controls.Add(pageHome);
        }

        void UpdateHomeStatus()
        {
            if (scanning)
            {
                shield.Set(Theme.Accent, false);
                lblState.Text = "Scanning...";
                lblState.ForeColor = Theme.Text;
                lblStateDetail.Text = "Looking for worm files, fake shortcuts and leftovers";
            }
            else if (currentFindings.Count == 0)
            {
                shield.Set(Theme.Safe, true);
                lblState.Text = "You're protected";
                lblState.ForeColor = Theme.Text;
                lblStateDetail.Text = string.IsNullOrEmpty(AppData.Settings.LastScan)
                    ? "No scan has run yet"
                    : "Last scan: " + AppData.Settings.LastScan;
            }
            else
            {
                int crit = currentFindings.Count(x => x.Severity == Severity.Critical);
                shield.Set(crit > 0 ? Theme.Danger : Theme.Warn, false);
                lblState.Text = currentFindings.Count + " threat(s) found";
                lblState.ForeColor = crit > 0 ? Theme.Danger : Theme.Warn;
                lblStateDetail.Text = "Open Scan Results to review and fix them";
            }
            lblStats.Text = AppData.Settings.ScansDone + " scans run, " + AppData.Settings.ThreatsRemoved + " threats quarantined so far";
        }

        void SetScanningUi(bool on)
        {
            btnQuick.Visible = btnFull.Visible = btnFolder.Visible = !on;
            progress.Visible = lblScanStatus.Visible = lblScanCount.Visible = btnCancelScan.Visible = on;
            progress.Running = on;
            btnFix.Enabled = btnIgnore.Enabled = !on;
            btnCancelScan.Enabled = true;
            if (on) lblScanStatus.Text = "Preparing scan...";
        }

        // ---------- threats ----------

        void BuildThreatsPage()
        {
            pageThreats = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Window };
            lblThreatSummary = new Label { Text = "Nothing scanned yet", Font = Theme.H2, ForeColor = Theme.Text, Location = new Point(24, 22), AutoSize = true };
            btnFix = new RoundedButton("Fix Selected", Theme.Danger) { Location = new Point(24, 62), Size = new Size(150, 36) };
            btnIgnore = new RoundedButton("Ignore Selected", Theme.Neutral) { Location = new Point(186, 62), Size = new Size(150, 36) };
            btnOpenReports = new RoundedButton("Open Reports", Theme.Neutral) { Location = new Point(348, 62), Size = new Size(150, 36) };
            btnFix.Click += delegate { FixSelected(); };
            btnIgnore.Click += delegate { IgnoreSelected(); };
            btnOpenReports.Click += delegate { OpenFolder(AppData.ReportsDir); };

            listThreats = new ListView
            {
                Location = new Point(24, 112),
                Size = new Size(792, 500),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                View = View.Details,
                FullRowSelect = true,
                CheckBoxes = true,
                HideSelection = true,
                BackColor = Theme.Card,
                ForeColor = Theme.Text,
                BorderStyle = BorderStyle.None,
                Font = Theme.Body
            };
            Theme.StyleList(listThreats);
            listThreats.Columns.Add("Severity", 100);
            listThreats.Columns.Add("Type", 150);
            listThreats.Columns.Add("Location", 310);
            listThreats.Columns.Add("Details", 220);
            listThreats.Resize += delegate { FillLastColumn(listThreats); };
            FillLastColumn(listThreats);

            pageThreats.Controls.Add(lblThreatSummary);
            pageThreats.Controls.Add(btnFix);
            pageThreats.Controls.Add(btnIgnore);
            pageThreats.Controls.Add(btnOpenReports);
            pageThreats.Controls.Add(listThreats);
            Controls.Add(pageThreats);
        }

        void FillLastColumn(ListView lv)
        {
            if (lv.Columns.Count == 0) return;
            int others = 0;
            for (int i = 0; i < lv.Columns.Count - 1; i++) others += lv.Columns[i].Width;
            int w = lv.ClientSize.Width - others;
            if (w > 40) lv.Columns[lv.Columns.Count - 1].Width = w;
        }

        void PopulateThreats()
        {
            listThreats.BeginUpdate();
            listThreats.Items.Clear();
            foreach (Finding f in currentFindings)
            {
                var item = new ListViewItem(f.Severity == Severity.Critical ? "CRITICAL" : f.Severity == Severity.Suspicious ? "SUSPICIOUS" : "INFO");
                item.SubItems.Add(f.TypeName);
                item.SubItems.Add(f.Path);
                item.SubItems.Add(f.Detail);
                item.Checked = true;
                item.ForeColor = f.Severity == Severity.Critical ? Theme.Danger : f.Severity == Severity.Suspicious ? Theme.Warn : Theme.Dim;
                item.Tag = f;
                listThreats.Items.Add(item);
            }
            listThreats.EndUpdate();
            lblThreatSummary.Text = currentFindings.Count == 0
                ? "No threats found in the last scan"
                : currentFindings.Count + " finding(s), " + currentFindings.Count(x => x.Severity == Severity.Critical) + " critical";
        }

        List<Finding> CheckedFindings()
        {
            return listThreats.Items.Cast<ListViewItem>().Where(i => i.Checked).Select(i => (Finding)i.Tag).ToList();
        }

        void FixSelected()
        {
            List<Finding> items = CheckedFindings();
            if (items.Count == 0)
            {
                MessageBox.Show("Tick the items you want to fix first.", "Fix", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (!Engine.IsElevated() && Fixer.NeedsElevation(items))
            {
                DialogResult r = MessageBox.Show(
                    "Some of these items (scheduled tasks, registry, Defender settings) can only be fixed from an administrator account.\n\nRestart as administrator now?",
                    "Administrator needed", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (r == DialogResult.Yes) RelaunchElevated();
                return;
            }

            DialogResult ok = MessageBox.Show(
                items.Count + " item(s) will be removed. Files go to quarantine, so they can be restored if something breaks.\n\nContinue?",
                "Fix items", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (ok != DialogResult.Yes) return;

            btnFix.Enabled = false;
            SetStatus("Fixing " + items.Count + " item(s)...");
            Task.Run((Action)delegate
            {
                FixResult result = null;
                try { result = Fixer.Fix(items, s => AppData.Log(s)); }
                catch (Exception ex) { AppData.Log("Fix crashed: " + ex); }
                SafeUi(delegate
                {
                    btnFix.Enabled = true;
                    SetStatus("Ready");
                    AppData.SaveSettings();
                    if (result != null)
                        MessageBox.Show("Done. " + result.Fixed + " fixed, " + result.Failed + " could not be removed.",
                            "Fix", MessageBoxButtons.OK, result.Failed == 0 ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
                    RunScan(lastOptions.Kind, lastOptions.CustomFolder);
                });
            });
        }

        void IgnoreSelected()
        {
            List<Finding> items = CheckedFindings();
            if (items.Count == 0)
            {
                MessageBox.Show("Tick the items you want to ignore.", "Ignore", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            DialogResult ok = MessageBox.Show(
                "Ignored items are skipped by future scans. Only ignore things you are sure are safe.\n\nIgnore " + items.Count + " item(s)?",
                "Ignore", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (ok != DialogResult.Yes) return;
            foreach (Finding f in items)
            {
                AppData.AddWhitelist(f.Path);
                currentFindings.Remove(f);
            }
            PopulateThreats();
            UpdateHomeStatus();
        }

        void RelaunchElevated()
        {
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath) { Verb = "runas", UseShellExecute = true });
                reallyExit = true;
                Application.Exit();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not restart as administrator: " + ex.Message, "Administrator", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // ---------- quarantine ----------

        void BuildQuarantinePage()
        {
            pageQuarantine = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Window };
            var lblTitle = new Label { Text = "Quarantine", Font = Theme.H2, ForeColor = Theme.Text, Location = new Point(24, 22), AutoSize = true };
            var lblDesc = new Label { Text = "Files moved here are kept but inactive. Restore them if something was a false alarm.", Font = Theme.Small, ForeColor = Theme.Dim, Location = new Point(24, 48), AutoSize = true };

            var btnRestore = new RoundedButton("Restore", Theme.Safe) { Location = new Point(24, 74), Size = new Size(130, 34) };
            var btnDelete = new RoundedButton("Delete Permanently", Theme.Danger) { Location = new Point(166, 74), Size = new Size(170, 34) };
            var btnOpenQ = new RoundedButton("Open Folder", Theme.Neutral) { Location = new Point(348, 74), Size = new Size(130, 34) };

            listQuarantine = new ListView
            {
                Location = new Point(24, 124),
                Size = new Size(792, 488),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                View = View.Details,
                FullRowSelect = true,
                BackColor = Theme.Card,
                ForeColor = Theme.Text,
                BorderStyle = BorderStyle.None,
                Font = Theme.Body
            };
            Theme.StyleList(listQuarantine);
            listQuarantine.Columns.Add("Date", 130);
            listQuarantine.Columns.Add("Threat", 200);
            listQuarantine.Columns.Add("Original location", 440);
            listQuarantine.Resize += delegate { FillLastColumn(listQuarantine); };
            FillLastColumn(listQuarantine);

            btnRestore.Click += delegate
            {
                if (listQuarantine.SelectedItems.Count == 0) return;
                var e = (QuarantineEntry)listQuarantine.SelectedItems[0].Tag;
                if (Quarantine.Restore(e, s => AppData.Log(s)))
                {
                    RefreshQuarantineList();
                    MessageBox.Show("Restored to its original location.", "Quarantine", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else MessageBox.Show("Restore failed, see the log for details.", "Quarantine", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            };
            btnDelete.Click += delegate
            {
                if (listQuarantine.SelectedItems.Count == 0) return;
                var e = (QuarantineEntry)listQuarantine.SelectedItems[0].Tag;
                DialogResult r = MessageBox.Show("Delete this file permanently?\n\n" + e.OriginalPath, "Quarantine",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (r == DialogResult.Yes && Quarantine.DeleteForever(e, s => AppData.Log(s))) RefreshQuarantineList();
            };
            btnOpenQ.Click += delegate { OpenFolder(AppData.QuarantineDir); };

            pageQuarantine.Controls.Add(lblTitle);
            pageQuarantine.Controls.Add(lblDesc);
            pageQuarantine.Controls.Add(btnRestore);
            pageQuarantine.Controls.Add(btnDelete);
            pageQuarantine.Controls.Add(btnOpenQ);
            pageQuarantine.Controls.Add(listQuarantine);
            Controls.Add(pageQuarantine);
        }

        void RefreshQuarantineList()
        {
            listQuarantine.BeginUpdate();
            listQuarantine.Items.Clear();
            foreach (QuarantineEntry e in Quarantine.Entries)
            {
                var item = new ListViewItem(e.Date);
                item.SubItems.Add(e.Threat);
                item.SubItems.Add(e.OriginalPath);
                item.Tag = e;
                listQuarantine.Items.Add(item);
            }
            listQuarantine.EndUpdate();
        }

        // ---------- settings ----------

        void BuildSettingsPage()
        {
            pageSettings = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Window };

            var usbCard = new Card { Location = new Point(24, 24), Size = new Size(792, 72), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            var lblUsb = new Label { Text = "Scan USB drives when they are connected", Font = Theme.Body, ForeColor = Theme.Text, Location = new Point(20, 14), AutoSize = true, BackColor = Theme.Card };
            var lblUsbDesc = new Label { Text = "Part of real-time protection", Font = Theme.Small, ForeColor = Theme.Dim, Location = new Point(20, 38), AutoSize = true, BackColor = Theme.Card };
            toggleUsb = new ToggleSwitch { Location = new Point(720, 24), BackColor = Theme.Card };
            toggleUsb.CheckedChanged += delegate
            {
                AppData.Settings.ScanUsb = toggleUsb.Checked;
                AppData.SaveSettings();
            };
            usbCard.Controls.Add(lblUsb);
            usbCard.Controls.Add(lblUsbDesc);
            usbCard.Controls.Add(toggleUsb);

            var startCard = new Card { Location = new Point(24, 108), Size = new Size(792, 72), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            var lblStart = new Label { Text = "Start with Windows", Font = Theme.Body, ForeColor = Theme.Text, Location = new Point(20, 14), AutoSize = true, BackColor = Theme.Card };
            var lblStartDesc = new Label { Text = "So real-time protection is always on", Font = Theme.Small, ForeColor = Theme.Dim, Location = new Point(20, 38), AutoSize = true, BackColor = Theme.Card };
            toggleStartWith = new ToggleSwitch { Location = new Point(720, 24), BackColor = Theme.Card };
            toggleStartWith.CheckedChanged += delegate { SetStartWithWindows(toggleStartWith.Checked); };
            startCard.Controls.Add(lblStart);
            startCard.Controls.Add(lblStartDesc);
            startCard.Controls.Add(toggleStartWith);

            var wlCard = new Card { Location = new Point(24, 192), Size = new Size(792, 178), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            var lblWl = new Label { Text = "Ignored items", Font = Theme.H2, ForeColor = Theme.Text, Location = new Point(20, 14), AutoSize = true, BackColor = Theme.Card };
            listWhitelist = new ListBox
            {
                Location = new Point(20, 46),
                Size = new Size(600, 110),
                BackColor = Theme.FromHex("22242E"),
                ForeColor = Theme.Text,
                BorderStyle = BorderStyle.None,
                Font = Theme.Small
            };
            var btnWlRemove = new RoundedButton("Remove Selected", Theme.Neutral) { Location = new Point(640, 80), Size = new Size(130, 32) };
            btnWlRemove.Click += delegate
            {
                if (listWhitelist.SelectedItem != null)
                {
                    AppData.RemoveWhitelist(listWhitelist.SelectedItem.ToString());
                    RefreshSettingsUi();
                }
            };
            wlCard.Controls.Add(lblWl);
            wlCard.Controls.Add(listWhitelist);
            wlCard.Controls.Add(btnWlRemove);

            var toolsCard = new Card { Location = new Point(24, 382), Size = new Size(792, 100), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            var lblTools = new Label { Text = "Folder tools", Font = Theme.H2, ForeColor = Theme.Text, Location = new Point(20, 14), AutoSize = true, BackColor = Theme.Card };
            var lblToolsDesc = new Label { Text = "Unhide folders a worm locked away on a drive:", Font = Theme.Small, ForeColor = Theme.Dim, Location = new Point(20, 44), AutoSize = true, BackColor = Theme.Card };
            comboUnhide = new ComboBox { Location = new Point(20, 64), Width = 110, DropDownStyle = ComboBoxStyle.DropDownList, BackColor = Theme.FromHex("22242E"), ForeColor = Theme.Text, FlatStyle = FlatStyle.Flat };
            var btnUnhide = new RoundedButton("Unhide Folders", Theme.Accent) { Location = new Point(140, 62), Size = new Size(140, 28) };
            var btnData = new RoundedButton("Open Data Folder", Theme.Neutral) { Location = new Point(292, 62), Size = new Size(150, 28) };
            btnUnhide.Click += delegate
            {
                if (comboUnhide.SelectedItem == null) return;
                string root = comboUnhide.SelectedItem.ToString();
                Task.Run((Action)delegate
                {
                    int n = Fixer.UnhideDriveFolders(root, s => AppData.Log(s));
                    SafeUi(delegate { MessageBox.Show(n + " folder(s) unhidden on " + root, "Unhide", MessageBoxButtons.OK, MessageBoxIcon.Information); });
                });
            };
            btnData.Click += delegate { OpenFolder(AppData.Root); };
            toolsCard.Controls.Add(lblTools);
            toolsCard.Controls.Add(lblToolsDesc);
            toolsCard.Controls.Add(comboUnhide);
            toolsCard.Controls.Add(btnUnhide);
            toolsCard.Controls.Add(btnData);

            var aboutCard = new Card { Location = new Point(24, 494), Size = new Size(792, 100), Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            lblAbout = new Label
            {
                Text = "Shortcut Virus Remover " + Program.AppVersion,
                Font = Theme.H2, ForeColor = Theme.Text, Location = new Point(20, 16), AutoSize = true, BackColor = Theme.Card
            };
            var lblAboutDesc = new Label
            {
                Text = "Removes USB shortcut worms and repairs the damage they leave behind.\r\nBuilt by Md. Rohan. This is a focused remover, not a replacement for Windows Defender.",
                Font = Theme.Small, ForeColor = Theme.Dim, Location = new Point(20, 46), AutoSize = true, BackColor = Theme.Card
            };
            aboutCard.Controls.Add(lblAbout);
            aboutCard.Controls.Add(lblAboutDesc);

            pageSettings.Controls.Add(usbCard);
            pageSettings.Controls.Add(startCard);
            pageSettings.Controls.Add(wlCard);
            pageSettings.Controls.Add(toolsCard);
            pageSettings.Controls.Add(aboutCard);
            Controls.Add(pageSettings);
        }

        const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string RunKeyName = "ShortcutVirusRemover";

        bool GetStartWithWindows()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(RunKeyPath))
                    return k != null && k.GetValue(RunKeyName) != null;
            }
            catch { return false; }
        }

        void SetStartWithWindows(bool on)
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(RunKeyPath, true))
                {
                    if (k == null) return;
                    if (on) k.SetValue(RunKeyName, "\"" + Application.ExecutablePath + "\"");
                    else k.DeleteValue(RunKeyName, false);
                }
                AppData.Log("Start with Windows " + (on ? "enabled" : "disabled"));
            }
            catch (Exception ex) { AppData.Log("StartWithWindows failed: " + ex.Message); }
        }

        void RefreshSettingsUi()
        {
            toggleUsb.Checked = AppData.Settings.ScanUsb;
            toggleStartWith.Checked = GetStartWithWindows();
            listWhitelist.Items.Clear();
            foreach (string w in AppData.WhitelistSnapshot()) listWhitelist.Items.Add(w);

            comboUnhide.Items.Clear();
            try
            {
                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    try { if (d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable)) comboUnhide.Items.Add(d.RootDirectory.FullName); }
                    catch { }
                }
                if (comboUnhide.Items.Count > 0) comboUnhide.SelectedIndex = 0;
            }
            catch { }
        }

        // ---------- tray ----------

        void SetupTray()
        {
            tray = new NotifyIcon { Icon = Icon, Text = "Shortcut Virus Remover", Visible = true };
            var menu = new ContextMenuStrip();
            menu.Items.Add("Open", null, delegate { RestoreFromTray(); });
            menu.Items.Add("Quick Scan", null, delegate { RestoreFromTray(); RunScan(ScanKind.Quick); });
            var pauseItem = new ToolStripMenuItem("Pause real-time protection");
            pauseItem.Click += delegate
            {
                pauseItem.Checked = !pauseItem.Checked;
                AppData.Settings.RealTime = !pauseItem.Checked;
                AppData.SaveSettings();
                if (protection != null) protection.Paused = pauseItem.Checked;
                toggleRealtime.Checked = !pauseItem.Checked;
                TrayNotify(pauseItem.Checked ? "Real-time protection paused" : "Real-time protection is back on", false);
            };
            menu.Items.Add(pauseItem);
            menu.Items.Add("Exit", null, delegate { reallyExit = true; Close(); });
            tray.ContextMenuStrip = menu;
            tray.DoubleClick += delegate { RestoreFromTray(); };
        }

        void RestoreFromTray()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        void StartRealtime()
        {
            protection = new RealTimeProtection();
            protection.Log = s => AppData.Log(s);
            protection.Notify = (text, warning) => TrayNotify(text, warning);
            protection.Paused = !AppData.Settings.RealTime;
            protection.Start();
        }

        void TrayNotify(string text, bool warning)
        {
            try
            {
                tray.BalloonTipTitle = "Shortcut Virus Remover";
                tray.BalloonTipText = text;
                tray.BalloonTipIcon = warning ? ToolTipIcon.Warning : ToolTipIcon.Info;
                tray.ShowBalloonTip(4000);
            }
            catch { }
            AppData.Log("Real-time: " + text);
        }

        void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (!reallyExit && scanning)
            {
                DialogResult r = MessageBox.Show("A scan is running. Stop it and exit?", "Exit", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (r != DialogResult.Yes) { e.Cancel = true; return; }
                cancelRequested = true;
            }
            if (!reallyExit)
            {
                // the tray keeps protecting after the window is closed
                e.Cancel = true;
                Hide();
                if (!trayHintShown)
                {
                    trayHintShown = true;
                    TrayNotify("Still protecting your PC. Double-click the tray icon to reopen.", false);
                }
                return;
            }
            if (protection != null) protection.Stop();
            if (tray != null) tray.Visible = false;
            uiTimer.Stop();
        }

        // ---------- scanning ----------

        void RunScan(ScanKind kind) { RunScan(kind, null); }

        void RunScan(ScanKind kind, string folder)
        {
            if (scanning)
            {
                MessageBox.Show("A scan is already running.", "Scan", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            scanning = true;
            cancelRequested = false;
            lastOptions = new ScanOptions { Kind = kind, CustomFolder = folder, Elevated = Engine.IsElevated() };

            SetScanningUi(true);
            UpdateHomeStatus();

            var ctx = new ScanContext();
            activeCtx = ctx;
            ctx.Cancelled = delegate { return cancelRequested; };
            ctx.Status = s => SafeUi(delegate { lblScanStatus.Text = s; });
            ctx.Log = s => AppData.Log(s);

            Task.Run((Action)delegate
            {
                try { ScanEngine.RunScan(lastOptions, ctx); }
                catch (OperationCanceledException) { ctx.Log("Scan cancelled"); }
                catch (Exception ex) { ctx.Log("Scan crashed: " + ex.Message); }
                SafeUi(delegate { ScanDone(ctx); });
            });
        }

        void ScanDone(ScanContext ctx)
        {
            scanning = false;
            SetScanningUi(false);
            bool wasCancelled = cancelRequested;
            currentFindings = ctx.Found;
            PopulateThreats();

            AppData.Settings.ScansDone++;
            AppData.Settings.LastScan = DateTime.Now.ToString("f");
            AppData.SaveSettings();
            AppData.WriteReport(ctx, lastOptions);
            UpdateHomeStatus();

            if (wasCancelled)
            {
                shield.Set(Theme.Warn, false);
                lblState.Text = "Scan cancelled";
                lblState.ForeColor = Theme.Warn;
                return;
            }

            if (ctx.Found.Count == 0)
            {
                ShowPage(pageHome);
            }
            else
            {
                ShowPage(pageThreats);
                TrayNotify(ctx.Found.Count + " threat(s) found, " + ctx.Found.Count(x => x.Severity == Severity.Critical) + " critical", true);
            }
        }

        void SetStatus(string s)
        {
            if (lblScanStatus != null && lblScanStatus.Visible) lblScanStatus.Text = s;
        }

        void SafeUi(Action a)
        {
            try
            {
                if (IsHandleCreated && !IsDisposed) BeginInvoke(a);
            }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }

        void OpenFolder(string path)
        {
            try
            {
                if (!Directory.Exists(path)) Directory.CreateDirectory(path);
                Process.Start("explorer.exe", "\"" + path + "\"");
            }
            catch { }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (uiTimer != null) uiTimer.Dispose();
                if (tray != null) { tray.Visible = false; tray.Dispose(); }
            }
            base.Dispose(disposing);
        }
    }
}
