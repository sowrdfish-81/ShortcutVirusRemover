using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ShortcutVirusRemover
{
    static class Theme
    {
        public static Color FromHex(string hex)
        {
            return Color.FromArgb(255,
                Convert.ToInt32(hex.Substring(0, 2), 16),
                Convert.ToInt32(hex.Substring(2, 2), 16),
                Convert.ToInt32(hex.Substring(4, 2), 16));
        }

        public static readonly Color Window = FromHex("20222B");
        public static readonly Color Sidebar = FromHex("191B22");
        public static readonly Color Card = FromHex("282B36");
        public static readonly Color CardHover = FromHex("2E323F");
        public static readonly Color Border = FromHex("343846");
        public static readonly Color Text = FromHex("E9EBF2");
        public static readonly Color Dim = FromHex("9BA1B3");
        public static readonly Color Accent = FromHex("4D8DF5");
        public static readonly Color Safe = FromHex("48B580");
        public static readonly Color Danger = FromHex("E05B5B");
        public static readonly Color Warn = FromHex("DFA93F");
        public static readonly Color Neutral = FromHex("3A3F4F");

        public static readonly Font Title = new Font("Segoe UI Semibold", 15.5F);
        public static readonly Font H2 = new Font("Segoe UI Semibold", 11.5F);
        public static readonly Font Body = new Font("Segoe UI", 9.5F);
        public static readonly Font Small = new Font("Segoe UI", 8.5F);

        // dark column headers for the list views
        public static void StyleList(ListView lv)
        {
            lv.OwnerDraw = true;
            lv.DrawColumnHeader += (s, e) =>
            {
                using (var b = new SolidBrush(FromHex("22242E"))) e.Graphics.FillRectangle(b, e.Bounds);
                TextRenderer.DrawText(e.Graphics, e.Header.Text, Body, e.Bounds, Dim,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
            };
            lv.DrawSubItem += (s, e) => { e.DrawDefault = true; };
        }

        public static GraphicsPath RoundPath(Rectangle r, int radius)
        {
            var p = new GraphicsPath();
            int d = radius * 2;
            if (d > r.Width) d = r.Width;
            if (d > r.Height) d = r.Height;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public static Bitmap MakeShield(int size, Color fill, bool withCheck)
        {            var bmp = new Bitmap(size, size);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                float w = size, h = size;
                var pts = new[]
                {
                    new PointF(0.5f * w, 0.04f * h),
                    new PointF(0.92f * w, 0.18f * h),
                    new PointF(0.92f * w, 0.52f * h),
                    new PointF(0.5f * w, 0.97f * h),
                    new PointF(0.08f * w, 0.52f * h),
                    new PointF(0.08f * w, 0.18f * h)
                };
                using (var path = new GraphicsPath())
                {
                    path.AddCurve(pts);
                    path.CloseFigure();
                    using (var b = new SolidBrush(fill)) g.FillPath(b, path);
                    using (var pen = new Pen(ControlPaint.Light(fill, 0.25f), size / 24f)) g.DrawPath(pen, path);
                }
                if (withCheck)
                {
                    using (var pen = new Pen(Color.White, size / 12f))
                    {
                        pen.StartCap = LineCap.Round;
                        pen.EndCap = LineCap.Round;
                        pen.LineJoin = LineJoin.Round;
                        g.DrawLines(pen, new[]
                        {
                            new PointF(0.32f * w, 0.52f * h),
                            new PointF(0.45f * w, 0.65f * h),
                            new PointF(0.70f * w, 0.36f * h)
                        });
                    }
                }
            }
            return bmp;
        }
    }

    // rounded panel, children go inside it
    class Card : Panel
    {        public Card()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Window;
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            using (var b = new SolidBrush(Parent != null ? Parent.BackColor : Theme.Window))
                e.Graphics.FillRectangle(b, ClientRectangle);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var r = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = Theme.RoundPath(r, 12))
            {
                using (var b = new SolidBrush(Theme.Card)) e.Graphics.FillPath(b, path);
                using (var pen = new Pen(Theme.Border)) e.Graphics.DrawPath(pen, path);
            }
        }
    }

    class RoundedButton : Control
    {
        readonly Color normal;
        bool hover, pressed;

        public RoundedButton(string text, Color color)
        {
            Text = text;
            normal = color;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.StandardClick, true);
            Size = new Size(150, 36);
            Cursor = Cursors.Hand;
            Font = new Font("Segoe UI Semibold", 9.5F);
            BackColor = Theme.Window;
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            using (var b = new SolidBrush(Parent != null ? Parent.BackColor : Theme.Window))
                e.Graphics.FillRectangle(b, ClientRectangle);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var r = new Rectangle(0, 0, Width - 1, Height - 1);
            Color back = normal;
            if (!Enabled) back = ControlPaint.Dark(normal, 0.35f);
            else if (pressed) back = ControlPaint.Dark(normal, 0.12f);
            else if (hover) back = ControlPaint.Light(normal, 0.12f);
            using (var path = Theme.RoundPath(r, 8))
            using (var b = new SolidBrush(back))
                e.Graphics.FillPath(b, path);
            TextRenderer.DrawText(e.Graphics, Text, Font, r,
                Enabled ? ForeColor : Theme.Dim,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; pressed = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { pressed = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { pressed = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }
    }

    class ToggleSwitch : Control
    {
        bool checkedState;
        public event EventHandler CheckedChanged;

        public bool Checked
        {
            get { return checkedState; }
            set
            {
                if (checkedState == value) return;
                checkedState = value;
                Invalidate();
                if (CheckedChanged != null) CheckedChanged(this, EventArgs.Empty);
            }
        }

        public ToggleSwitch()
        {
            Size = new Size(48, 24);
            Cursor = Cursors.Hand;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            using (var b = new SolidBrush(Parent != null ? Parent.BackColor : Theme.Card))
                e.Graphics.FillRectangle(b, ClientRectangle);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var track = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = Theme.RoundPath(track, track.Height / 2))
            using (var b = new SolidBrush(checkedState ? Theme.Safe : Theme.Border))
                e.Graphics.FillPath(b, path);
            int knob = Height - 6;
            int x = checkedState ? Width - knob - 3 : 3;
            using (var b = new SolidBrush(Color.White))
                e.Graphics.FillEllipse(b, x, 3, knob, knob);
        }

        protected override void OnClick(EventArgs e)
        {
            Checked = !Checked;
            base.OnClick(e);
        }
    }

    class MarqueeBar : Control
    {
        readonly Timer timer = new Timer();
        float pos = -0.25f;
        bool running;

        public MarqueeBar()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Height = 8;
            timer.Interval = 16;
            timer.Tick += delegate
            {
                if (!running) return;
                pos += 0.012f;
                if (pos > 1.15f) pos = -0.25f;
                Invalidate();
            };
        }

        public bool Running
        {
            get { return running; }
            set
            {
                running = value;
                pos = -0.25f;
                if (running) timer.Start();
                else { timer.Stop(); Invalidate(); }
            }
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            using (var b = new SolidBrush(Parent != null ? Parent.BackColor : Theme.Card))
                e.Graphics.FillRectangle(b, ClientRectangle);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var r = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = Theme.RoundPath(r, 4))
            {
                using (var b = new SolidBrush(Theme.Border)) e.Graphics.FillPath(b, path);
                if (running)
                {
                    float w = Width * 0.22f;
                    float x = pos * (Width + w) - w;
                    e.Graphics.SetClip(path);
                    using (var b = new SolidBrush(Theme.Accent)) e.Graphics.FillRectangle(b, x, 0, w, Height);
                    e.Graphics.ResetClip();
                }
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) timer.Dispose();
            base.Dispose(disposing);
        }
    }

    class ShieldView : Control
    {
        Image image;
        string state = "";

        public ShieldView()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Size = new Size(84, 84);
        }

        public void Set(Color color, bool check)
        {
            string key = color.ToArgb() + "|" + check;
            if (key == state) return;
            state = key;
            if (image != null) image.Dispose();
            image = Theme.MakeShield(Math.Max(Width, 1), color, check);
            Invalidate();
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            using (var b = new SolidBrush(Parent != null ? Parent.BackColor : Theme.Card))
                e.Graphics.FillRectangle(b, ClientRectangle);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            if (image != null) e.Graphics.DrawImage(image, 0, 0, Width, Height);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && image != null) image.Dispose();
            base.Dispose(disposing);
        }
    }

    class NavButton : Control
    {
        bool selected, hover;

        public bool Selected
        {
            get { return selected; }
            set { selected = value; Invalidate(); }
        }

        public NavButton(string text)
        {
            Text = text;
            Size = new Size(180, 40);
            Font = new Font("Segoe UI", 10F);
            Cursor = Cursors.Hand;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            using (var b = new SolidBrush(Theme.Sidebar)) e.Graphics.FillRectangle(b, ClientRectangle);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (selected)
            {
                using (var b = new SolidBrush(Theme.CardHover)) e.Graphics.FillRectangle(b, 0, 4, Width, Height - 8);
                using (var b = new SolidBrush(Theme.Accent)) e.Graphics.FillRectangle(b, 0, 4, 3, Height - 8);
            }
            else if (hover)
            {
                using (var b = new SolidBrush(Color.FromArgb(22, 255, 255, 255))) e.Graphics.FillRectangle(b, 0, 4, Width, Height - 8);
            }
            TextRenderer.DrawText(e.Graphics, Text, Font, new Rectangle(18, 0, Width - 18, Height),
                selected ? Theme.Text : Theme.Dim,
                TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }

        protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }
    }
}
