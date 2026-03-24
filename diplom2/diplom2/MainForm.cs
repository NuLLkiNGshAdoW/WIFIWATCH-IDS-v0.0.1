using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Linq;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.IO;
using System.Text;
using System.Runtime.Versioning;
using System.Net.Http;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Threading;
#if !NOSNIFF
using PacketDotNet;
using SharpPcap;
#endif
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

[assembly: SupportedOSPlatform("windows")]

namespace diplom2
{
    public partial class MainForm : Form
    {
        // ── Stats labels
        private Label lblTotal = null!, lblSafe = null!, lblWarn = null!, lblDanger = null!;

        // ── Main grid
        private DataGridView dgv = null!;

        // ── Log
        private RichTextBox rtbLog = null!;

        // ── AI chat panel (right side)
        private Panel pnlAIChat = null!;
        private RichTextBox rtbAIChat = null!;
        private TextBox txtAIInput = null!;
        private bool aiPanelVisible = false;

        // ── Site monitor timer
        private System.Windows.Forms.Timer? siteTimer;
        private Dictionary<string, string> ipToSite = new();
        // Sniffer
        private bool snifferRunning = false;
#if !NOSNIFF
        private ICaptureDevice? captureDevice = null;
#else
        // When NOSNIFF is defined we don't reference SharpPcap types.
        private object? captureDevice = null;
#endif

        // ── Counters
        private int totalCount = 0, safeCount = 0, warnCount = 0, dangerCount = 0;

        // ── Gemini
        private const string MyGeminiKey = "AIzaSyByH9wXcZw7XrmljAO9NY8pnttiQKarOIg";
        private const string ApiUrl = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=";

        // ── White-list
        private List<string> whiteList = new() { "00:50:56", "B4:B5:B6", "6C:72:E2" };

        // ── Theme
        private static readonly Color BG = Color.FromArgb(13, 17, 23);
        private static readonly Color BG2 = Color.FromArgb(22, 27, 34);
        private static readonly Color BG3 = Color.FromArgb(30, 37, 46);
        private static readonly Color BG4 = Color.FromArgb(36, 44, 54);
        private static readonly Color ACCENT = Color.FromArgb(88, 166, 255);
        private static readonly Color SAFE = Color.FromArgb(63, 185, 80);
        private static readonly Color WARN = Color.FromArgb(210, 153, 34);
        private static readonly Color DANGER = Color.FromArgb(248, 81, 73);
        private static readonly Color TEXT = Color.FromArgb(230, 237, 243);
        private static readonly Color SUBTEXT = Color.FromArgb(125, 133, 144);
        private static readonly Color BORDER = Color.FromArgb(48, 54, 61);

        public MainForm()
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            InitializeComponent();
            SetupInterface();
            StartSiteMonitor();
        }

        private async Task<Dictionary<string, string>> DiscoverMdns(int timeoutMs)
        {
            var result = new Dictionary<string, string>();
            try
            {
                using var client = new UdpClient();
                client.EnableBroadcast = true;
                client.MulticastLoopback = false;
                var mdnsEP = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);

                // Simple mDNS query for PTR _services for local names is complex; query for A of common .local names via wildcard
                byte[] query = BuildMdnsQueryBytes();
                await client.SendAsync(query, query.Length, mdnsEP);

                var sw = Stopwatch.StartNew();
                while (sw.ElapsedMilliseconds < timeoutMs)
                {
                    var task = client.ReceiveAsync();
                    var t = await Task.WhenAny(task, Task.Delay(200));
                    if (t != task) continue;
                    var res = task.Result;
                    var remoteIp = ((IPEndPoint)res.RemoteEndPoint).Address.ToString();
                    string parsed = ParseMdnsForName(res.Buffer);
                    if (!string.IsNullOrEmpty(parsed) && !result.ContainsKey(remoteIp))
                        result[remoteIp] = parsed;
                }
            }
            catch { }
            return result;
        }

        private byte[] BuildMdnsQueryBytes()
        {
            // Minimal DNS query asking for ANY at name "local." may not work everywhere.
            // We build a query with name "_http._tcp.local" PTR to discover HTTP services which many devices announce.
            using var ms = new MemoryStream();
            void W(ushort v) => ms.Write(BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder((short)v)), 0, 2);
            W((ushort)new Random().Next(1, ushort.MaxValue)); // id
            W(0); // flags
            W(1); // qdcount
            W(0); // ancount
            W(0);
            W(0);
            // name: _http._tcp.local
            void WriteLabel(string s)
            {
                ms.WriteByte((byte)s.Length);
                ms.Write(Encoding.ASCII.GetBytes(s), 0, s.Length);
            }
            WriteLabel("_http");
            WriteLabel("_tcp");
            WriteLabel("local");
            ms.WriteByte(0);
            W(12); // PTR
            W(1); // class IN
            return ms.ToArray();
        }

        private string ParseMdnsForName(byte[] buf)
        {
            try
            {
                // Very small parser: look for ASCII labels ending with .local and return the label string
                string s = Encoding.ASCII.GetString(buf);
                var m = Regex.Match(s, "([a-zA-Z0-9-]+\\.local)", RegexOptions.IgnoreCase);
                if (m.Success) return m.Groups[1].Value.Trim();
            }
            catch { }
            return "";
        }

#if !NOSNIFF
        private void CheckSniffer()
        {
            // Check for Npcap driver existence (simple check: presence of "Npcap" service)
            try
            {
                bool installed = false;
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Npcap");
                    installed = key != null;
                }
                catch { installed = false; }

                if (installed)
                {
                    // try to start sniffer
                    var dlg = MessageBox.Show("Npcap найден. Запустить сниффер (требуются права администратора)?", "Сниффер", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                    if (dlg == DialogResult.Yes)
                    {
                        try { StartSniffer(); }
                        catch (Exception ex) { MessageBox.Show("Не удалось запустить сниффер: " + ex.Message); }
                    }
                }
                else
                    MessageBox.Show("Npcap не найден. Чтобы видеть сайты всех устройств, установите Npcap (https://nmap.org/npcap/) и запустите приложение от имени администратора.", "Сниффер", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            catch (Exception ex) { MessageBox.Show("Проверка сниффера не удалась: " + ex.Message); }
        }

        private void StartSniffer()
        {
            if (snifferRunning) { MessageBox.Show("Сниффер уже запущен."); return; }
            try
            {
                var devices = CaptureDeviceList.Instance;
                if (devices == null || devices.Count < 1)
                {
                    MessageBox.Show("Сетевые устройства не найдены. Убедитесь, что Npcap установлен и у приложения есть права администратора.", "Сниффер", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    Log("[!] CaptureDeviceList empty. Npcap or privileges missing.", DANGER);
                    return;
                }

                // Log available devices
                var sb = new StringBuilder();
                for (int i = 0; i < devices.Count; i++)
                {
                    var d = devices[i];
                    sb.AppendLine($"[{i}] {d.Name} - {d.Description}");
                }
                Log("[i] Available capture devices:\n" + sb.ToString(), SUBTEXT);

                int chosen = 0;
                if (devices.Count > 1)
                {
                    // ask user to pick device
                    using var dlg = new Form();
                    dlg.Text = "Выберите интерфейс для сниффинга";
                    dlg.StartPosition = FormStartPosition.CenterParent;
                    dlg.Size = new Size(600, 320);
                    var list = new ListBox { Dock = DockStyle.Fill };
                    for (int i = 0; i < devices.Count; i++) list.Items.Add($"[{i}] {devices[i].Name} - {devices[i].Description}");
                    list.SelectedIndex = 0;
                    var btnPanel = new Panel { Dock = DockStyle.Bottom, Height = 42 };
                    var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Dock = DockStyle.Right, Width = 90 };
                    var cancel = new Button { Text = "Отмена", DialogResult = DialogResult.Cancel, Dock = DockStyle.Right, Width = 90 };
                    btnPanel.Controls.Add(cancel); btnPanel.Controls.Add(ok);
                    dlg.Controls.Add(list); dlg.Controls.Add(btnPanel);
                    if (dlg.ShowDialog(this) == DialogResult.OK)
                        chosen = list.SelectedIndex >= 0 ? list.SelectedIndex : 0;
                    else
                    {
                        Log("[i] Sniffer start cancelled by user.", SUBTEXT);
                        return;
                    }
                }

                captureDevice = devices[chosen];
                captureDevice.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);
                try
                {
                    captureDevice.Open(DeviceMode.Promiscuous, 1000);
                }
                catch (Exception exOpen)
                {
                    MessageBox.Show("Не удалось открыть устройство для захвата. Запустите приложение от имени администратора.\n" + exOpen.Message, "Сниффер", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Log("[!] Failed to open capture device: " + exOpen.Message, DANGER);
                    return;
                }

                captureDevice.StartCapture();
                snifferRunning = true;
                Log("[i] Sniffer started on device: " + captureDevice.Name, SUBTEXT);
            }
            catch (Exception ex) { MessageBox.Show("Ошибка при запуске сниффера: " + ex.Message); Log("[!] Sniffer start error: " + ex.Message, DANGER); }
        }

        private void StopSniffer()
        {
            if (!snifferRunning) return;
            try
            {
                captureDevice?.StopCapture();
                captureDevice?.Close();
                captureDevice = null;
                snifferRunning = false;
                Log("[i] Sniffer stopped.", SUBTEXT);
            }
            catch { }
        }

        private void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            try
            {
                var raw = e.Packet?.Data;
                if (raw == null || raw.Length == 0) return;
                var pkt = Packet.ParsePacket(e.Packet.LinkLayerType, raw);
                var ip = pkt.Extract<IpPacket>();
                if (ip == null) return;
                string src = ip.SourceAddress.ToString();
                string dst = ip.DestinationAddress.ToString();

                // Try to extract HTTP Host or TLS SNI from payload
                var tcp = pkt.Extract<TcpPacket>();
                if (tcp != null && tcp.PayloadData != null && tcp.PayloadData.Length > 0)
                {
                    string payload = Encoding.ASCII.GetString(tcp.PayloadData);
                    var m = Regex.Match(payload, "Host:\\s*(.+?)\\r?\\n", RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        string host = m.Groups[1].Value.Trim();
                        this.Invoke(new Action(() =>
                        {
                            if (!ipToSite.ContainsKey(src)) ipToSite[src] = host; else if (!ipToSite[src].Contains(host)) ipToSite[src] += ", " + host;
                        }));
                    }
                    else
                    {
                        // TLS ClientHello SNI check (binary) - simple search
                        var sni = ExtractSniFromTls(tcp.PayloadData);
                        if (!string.IsNullOrEmpty(sni))
                        {
                            this.Invoke(new Action(() =>
                            {
                                if (!ipToSite.ContainsKey(src)) ipToSite[src] = sni; else if (!ipToSite[src].Contains(sni)) ipToSite[src] += ", " + sni;
                            }));
                        }
                    }
                }
            }
            catch { }
        }
#endif

        private string? ExtractSniFromTls(byte[] data)
        {
            try
            {
                // Very small heuristics: look for "\x00\x00\x00" areas and ascii containing "." and no spaces
                string asAscii = Encoding.ASCII.GetString(data);
                var m = Regex.Match(asAscii, "([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
                if (m.Success) return m.Groups[1].Value;
            }
            catch { }
            return null;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  UI SETUP
        // ══════════════════════════════════════════════════════════════════════
        private void SetupInterface()
        {
            this.Text = "WIFIWATCH IDS";
            this.Size = new Size(1500, 920);
            this.MinimumSize = new Size(1200, 720);
            this.BackColor = BG;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Font = new Font("Segoe UI", 9f);

            // ── TOP HEADER BAR ──────────────────────────────────────────────
            Panel pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 52,
                BackColor = BG2
            };
            Panel headerBottom = new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = BORDER };

            Label lblTitle = new Label
            {
                Text = "◈  WIFIWATCH IDS",
                ForeColor = ACCENT,
                Font = new Font("Segoe UI Semibold", 14f),
                Location = new Point(20, 0),
                Size = new Size(260, 52),
                TextAlign = ContentAlignment.MiddleLeft
            };
            Label lblSub = new Label
            {
                Text = "Желілік мониторинг AI",
                ForeColor = SUBTEXT,
                Font = new Font("Segoe UI", 8.5f),
                Location = new Point(240, 0),
                Size = new Size(240, 52),
                TextAlign = ContentAlignment.MiddleLeft
            };

            // Copilot-style AI button — top right
            Button btnAIToggle = new Button
            {
                Size = new Size(44, 34),
                BackColor = Color.FromArgb(40, 36, 90),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = "",
                Anchor = AnchorStyles.Right | AnchorStyles.Top
            };
            btnAIToggle.FlatAppearance.BorderColor = Color.FromArgb(88, 80, 200);
            btnAIToggle.FlatAppearance.BorderSize = 1;
            btnAIToggle.Paint += (s, e) =>
            {
                var g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                int cx = btnAIToggle.Width / 2;
                int cy = btnAIToggle.Height / 2;
                using var penOuter = new Pen(Color.FromArgb(140, 130, 255), 2f);
                g.DrawEllipse(penOuter, cx - 12, cy - 12, 24, 24);
                using var penInner = new Pen(Color.FromArgb(180, 170, 255), 1.5f);
                g.DrawArc(penInner, cx - 7, cy - 7, 14, 14, -90, 240);
                using var brDot = new SolidBrush(Color.FromArgb(210, 200, 255));
                g.FillEllipse(brDot, cx - 3, cy - 3, 6, 6);
            };
            pnlHeader.Resize += (s, e) =>
            {
                btnAIToggle.Location = new Point(pnlHeader.Width - 58, 9);
            };
            btnAIToggle.Click += (s, e) => ToggleAIPanel();

            pnlHeader.Controls.Add(headerBottom);
            pnlHeader.Controls.Add(btnAIToggle);
            pnlHeader.Controls.Add(lblSub);
            pnlHeader.Controls.Add(lblTitle);

            // ── STATS BAR ────────────────────────────────────────────────────
            Panel pnlStats = new Panel
            {
                Dock = DockStyle.Top,
                Height = 82,
                BackColor = BG2,
                Padding = new Padding(16, 10, 16, 10)
            };
            Panel statsBottom = new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = BORDER };
            FlowLayoutPanel flow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false
            };
            lblTotal = MakeStatCard(flow, "БАРЛЫҚ ҚҰРЫЛҒЫЛАР", ACCENT);
            lblSafe = MakeStatCard(flow, "ҚАУІПСІЗ", SAFE);
            lblWarn = MakeStatCard(flow, "БЕЛГІСІЗ", WARN);
            lblDanger = MakeStatCard(flow, "ҚАУІПТІ", DANGER);
            pnlStats.Controls.Add(flow);
            pnlStats.Controls.Add(statsBottom);

            // ── AI CHAT PANEL (right, full height after header) ───────────────
            pnlAIChat = new Panel
            {
                Dock = DockStyle.Right,
                Width = 380,
                BackColor = BG2,
                Visible = false
            };
            // Purple left border = visual separator from main content
            Panel aiLeftBorder = new Panel
            {
                Dock = DockStyle.Left,
                Width = 2,
                BackColor = Color.FromArgb(88, 80, 200)
            };
            pnlAIChat.Controls.Add(aiLeftBorder);
            BuildAIChatPanel();

            // ── MAIN CONTENT AREA ────────────────────────────────────────────
            Panel pnlMain = new Panel { Dock = DockStyle.Fill, BackColor = BG };

            dgv = BuildGrid();

            // ── BOTTOM: LOG + TOOLBAR ─────────────────────────────────────────
            Panel pnlBottom = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 185,
                BackColor = BG2
            };
            Panel bottomTop = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = BORDER };

            rtbLog = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = BG,
                ForeColor = Color.FromArgb(80, 200, 120),
                Font = new Font("Cascadia Code", 8.5f),
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                Padding = new Padding(14, 8, 8, 8)
            };

            Panel pnlToolbar = new Panel
            {
                Dock = DockStyle.Right,
                Width = 210,
                BackColor = BG2
            };
            Panel toolLeft = new Panel { Dock = DockStyle.Left, Width = 1, BackColor = BORDER };

            FlowLayoutPanel toolFlow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(12, 12, 12, 12)
            };

            Button b1 = MakeDockBtn("⟳  СКАНЕРЛЕУ", ACCENT);
            Button b2 = MakeDockBtn("↓  ЕСЕП САҚТАУ", BG4);
            Button b3 = MakeDockBtn("🔎 СНИФФЕР", BG4);
            b2.ForeColor = SAFE;
            b2.FlatAppearance.BorderColor = BORDER;
            b2.FlatAppearance.BorderSize = 1;
            b3.ForeColor = SUBTEXT;
            b3.FlatAppearance.BorderColor = BORDER;
            b3.FlatAppearance.BorderSize = 1;

            b1.Click += async (s, e) => await RunNetworkScan();
            b2.Click += (s, e) => ExportData();
#if !NOSNIFF
            b3.Click += (s, e) => CheckSniffer();
#else
            b3.Click += (s, e) => MessageBox.Show("Сниффер недоступен: пакет SharpPcap не подключен или NOSNIFF активирован.", "Сниффер", MessageBoxButtons.OK, MessageBoxIcon.Information);
#endif

            toolFlow.Controls.Add(b1);
            toolFlow.Controls.Add(b2);
            toolFlow.Controls.Add(b3);
            pnlToolbar.Controls.Add(toolFlow);
            pnlToolbar.Controls.Add(toolLeft);

            pnlBottom.Controls.Add(rtbLog);
            pnlBottom.Controls.Add(pnlToolbar);
            pnlBottom.Controls.Add(bottomTop);

            pnlMain.Controls.Add(dgv);
            pnlMain.Controls.Add(pnlBottom);

            // ── ASSEMBLE ──────────────────────────────────────────────────────
            this.Controls.Add(pnlMain);
            this.Controls.Add(pnlAIChat);
            this.Controls.Add(pnlStats);
            this.Controls.Add(pnlHeader);
        }

        // ══════════════════════════════════════════════════════════════════════
        //  AI CHAT PANEL
        // ══════════════════════════════════════════════════════════════════════
        private void BuildAIChatPanel()
        {
            // Header aligned with main header (52px)
            Panel hdr = new Panel
            {
                Dock = DockStyle.Top,
                Height = 52,
                BackColor = BG3
            };
            Panel hdrBottom = new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = BORDER };

            Label lblHdr = new Label
            {
                Text = "✦  AI Қауіпсіздік Кеңесшісі",
                ForeColor = Color.FromArgb(180, 170, 255),
                Font = new Font("Segoe UI Semibold", 10f),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(14, 0, 0, 0)
            };
            Button btnClose = new Button
            {
                Text = "✕",
                Dock = DockStyle.Right,
                Width = 44,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Transparent,
                ForeColor = SUBTEXT,
                Font = new Font("Segoe UI", 11f),
                Cursor = Cursors.Hand
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => ToggleAIPanel();
            hdr.Controls.Add(btnClose);
            hdr.Controls.Add(lblHdr);
            hdr.Controls.Add(hdrBottom);

            // Chat display
            rtbAIChat = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = BG,
                ForeColor = TEXT,
                Font = new Font("Segoe UI", 9.5f),
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                ScrollBars = RichTextBoxScrollBars.Vertical,
                Padding = new Padding(14, 12, 14, 8)
            };
            AppendAIMsg("system", "Сәлем! Желілік қауіпсіздік туралы сұрақ қойыңыз.\n\nМысалы: «Бөтен құрылғы қалай блокталады?»");

            // Input area
            Panel pnlInput = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 86,
                BackColor = BG3,
                Padding = new Padding(12, 10, 12, 10)
            };
            Panel inputTop = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = BORDER };

            txtAIInput = new TextBox
            {
                Multiline = true,
                BackColor = BG4,
                ForeColor = TEXT,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 9.5f),
                Dock = DockStyle.Fill,
                ScrollBars = ScrollBars.None
            };
            txtAIInput.KeyDown += async (s, e) =>
            {
                if (e.KeyCode == Keys.Enter && !e.Shift)
                {
                    e.SuppressKeyPress = true;
                    await SendAIMessage();
                }
            };

            Button btnSend = new Button
            {
                Text = "➤",
                Dock = DockStyle.Right,
                Width = 44,
                BackColor = Color.FromArgb(88, 80, 200),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            btnSend.FlatAppearance.BorderSize = 0;
            btnSend.Click += async (s, e) => await SendAIMessage();

            pnlInput.Controls.Add(txtAIInput);
            pnlInput.Controls.Add(btnSend);
            pnlInput.Controls.Add(inputTop);

            pnlAIChat.Controls.Add(rtbAIChat);
            pnlAIChat.Controls.Add(pnlInput);
            pnlAIChat.Controls.Add(hdr);
        }

        private void ToggleAIPanel()
        {
            aiPanelVisible = !aiPanelVisible;
            pnlAIChat.Visible = aiPanelVisible;
        }

        private async Task SendAIMessage()
        {
            string prompt = txtAIInput.Text.Trim();
            if (string.IsNullOrEmpty(prompt)) return;
            AppendAIMsg("user", prompt);
            txtAIInput.Clear();
            AppendAIMsg("thinking", "Ойланып жатыр…");
            string response = await AskGemini(prompt);
            if (rtbAIChat.InvokeRequired) rtbAIChat.Invoke(new Action(RemoveLastLine));
            else RemoveLastLine();
            AppendAIMsg("ai", response);
        }

        private void RemoveLastLine()
        {
            var lines = rtbAIChat.Lines.ToList();
            if (lines.Count > 0) lines.RemoveAt(lines.Count - 1);
            rtbAIChat.Lines = lines.ToArray();
        }

        private void AppendAIMsg(string role, string text)
        {
            if (rtbAIChat == null) return;
            Action act = () =>
            {
                switch (role)
                {
                    case "system":
                        rtbAIChat.SelectionColor = Color.FromArgb(100, 94, 200);
                        rtbAIChat.SelectionFont = new Font("Segoe UI Semibold", 8f);
                        rtbAIChat.AppendText("──  ЖҮЙЕ  ──────────────────\n");
                        rtbAIChat.SelectionColor = Color.FromArgb(173, 214, 255);
                        rtbAIChat.SelectionFont = new Font("Segoe UI", 9.5f);
                        rtbAIChat.AppendText(text + "\n\n");
                        break;
                    case "user":
                        rtbAIChat.SelectionColor = ACCENT;
                        rtbAIChat.SelectionFont = new Font("Segoe UI Semibold", 9f);
                        rtbAIChat.AppendText("▸ Сіз\n");
                        rtbAIChat.SelectionColor = TEXT;
                        rtbAIChat.SelectionFont = new Font("Segoe UI", 9.5f);
                        rtbAIChat.AppendText(text + "\n\n");
                        break;
                    case "ai":
                        rtbAIChat.SelectionColor = Color.FromArgb(180, 170, 255);
                        rtbAIChat.SelectionFont = new Font("Segoe UI Semibold", 9f);
                        rtbAIChat.AppendText("✦ AI Кеңесші\n");
                        rtbAIChat.SelectionColor = TEXT;
                        rtbAIChat.SelectionFont = new Font("Segoe UI", 9.5f);
                        rtbAIChat.AppendText(text + "\n\n");
                        break;
                    case "thinking":
                        rtbAIChat.SelectionColor = SUBTEXT;
                        rtbAIChat.SelectionFont = new Font("Segoe UI", 9f, FontStyle.Italic);
                        rtbAIChat.AppendText(text + "\n");
                        break;
                }
                rtbAIChat.ScrollToCaret();
            };
            if (rtbAIChat.InvokeRequired) rtbAIChat.Invoke(act); else act();
        }

        // ══════════════════════════════════════════════════════════════════════
        //  SITE MONITOR — обновляет колонку «Сайттар» каждые 8 секунд
        // ══════════════════════════════════════════════════════════════════════
        private void StartSiteMonitor()
        {
            siteTimer = new System.Windows.Forms.Timer { Interval = 8000 };
            siteTimer.Tick += async (s, e) => await UpdateSiteInfo();
            siteTimer.Start();
        }

        private async Task UpdateSiteInfo()
        {
            var connections = await Task.Run(() => GetActiveConnections());
            ipToSite.Clear();
            foreach (var (localIp, remoteHost) in connections)
            {
                if (string.IsNullOrEmpty(remoteHost)) continue;
                string site = FriendlySiteName(remoteHost);
                if (ipToSite.ContainsKey(localIp))
                {
                    if (!ipToSite[localIp].Contains(site))
                        ipToSite[localIp] += ", " + site;
                }
                else
                    ipToSite[localIp] = site;
            }

            this.Invoke(new Action(() =>
            {
                // Debug: log collected site mappings
                foreach (var kv in ipToSite)
                    Log($"[i] sitemap: {kv.Key} => {kv.Value}", SUBTEXT);

                foreach (DataGridViewRow row in dgv.Rows)
                {
                    string? cellVal = row.Cells["Info"].Value?.ToString();
                    if (string.IsNullOrEmpty(cellVal)) continue;
                    // Try to find an IPv4 address anywhere in the cell (handles "hostname\nIP" or just IP)
                    var m = Regex.Match(cellVal, @"(\d+\.\d+\.\d+\.\d+)");
                    if (m.Success)
                    {
                        string ip = m.Groups[1].Value;
                        if (ipToSite.TryGetValue(ip, out string? sites))
                        {
                            row.Cells["Sites"].Value = sites;
                            Log($"[i] Updated row {ip} -> {sites}", SUBTEXT);
                        }
                        else
                        {
                            // no active connections found for this IP currently
                            Log($"[i] No site for {ip}", SUBTEXT);
                        }
                    }
                }
            }));
        }

        private List<(string localIp, string remoteHost)> GetActiveConnections()
        {
            var result = new List<(string, string)>();
            try
            {
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo("netstat", "-n -o")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                var matches = Regex.Matches(output,
                    @"TCP\s+(\d+\.\d+\.\d+\.\d+):\d+\s+(\d+\.\d+\.\d+\.\d+):\d+\s+ESTABLISHED",
                    RegexOptions.IgnoreCase);

                var resolved = new Dictionary<string, string>();
                foreach (Match m in matches)
                {
                    string localIp = m.Groups[1].Value;
                    string remoteIp = m.Groups[2].Value;
                    if (IsPrivateIp(remoteIp)) continue;
                    if (!resolved.TryGetValue(remoteIp, out string? host))
                    {
                        try { host = Dns.GetHostEntry(remoteIp).HostName; }
                        catch { host = remoteIp; }
                        resolved[remoteIp] = host;
                    }
                    result.Add((localIp, host!));
                }
            }
            catch { }
            return result;
        }

        private bool IsPrivateIp(string ip)
        {
            return ip.StartsWith("10.") || ip.StartsWith("192.168.") ||
                   ip.StartsWith("172.16.") || ip.StartsWith("172.17.") ||
                   ip.StartsWith("172.31.") || ip == "127.0.0.1";
        }

        private string FriendlySiteName(string host)
        {
            if (string.IsNullOrEmpty(host)) return "";
            host = host.ToLower();
            // If it's a plain IPv4 address, just return it (no friendly name)
            if (Regex.IsMatch(host, "^\\d+\\.\\d+\\.\\d+\\.\\d+$"))
                return host;
            if (host.Contains("youtube") || host.Contains("googlevideo")) return "YouTube 📺";
            if (host.Contains("google")) return "Google 🔍";
            if (host.Contains("facebook") || host.Contains("fbcdn")) return "Facebook 👤";
            if (host.Contains("instagram")) return "Instagram 📷";
            if (host.Contains("tiktok")) return "TikTok 🎵";
            if (host.Contains("netflix")) return "Netflix 🎬";
            if (host.Contains("amazon")) return "Amazon 🛒";
            if (host.Contains("twitter") || host.Contains("x.com")) return "X/Twitter 🐦";
            if (host.Contains("telegram")) return "Telegram ✈";
            if (host.Contains("whatsapp")) return "WhatsApp 💬";
            if (host.Contains("discord")) return "Discord 🎮";
            if (host.Contains("twitch")) return "Twitch 🟣";
            if (host.Contains("spotify")) return "Spotify 🎵";
            if (host.Contains("microsoft") || host.Contains("msn")) return "Microsoft 🪟";
            if (host.Contains("apple") || host.Contains("icloud")) return "Apple 🍎";
            if (host.Contains("zoom")) return "Zoom 📹";
            if (host.Contains("yandex")) return "Yandex 🌐";
            if (host.Contains("vk.com") || host.Contains("vkontakte")) return "VK 🔵";
            if (host.Contains("kaspi")) return "Kaspi 💳";
            if (host.Contains("cloudflare")) return "Cloudflare ☁";
            var parts = host.TrimStart('w', '.').Split('.');
            return parts.Length >= 2 ? parts[^2] + "." + parts[^1] : host;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  NETWORK SCAN
        // ══════════════════════════════════════════════════════════════════════
        private async Task RunNetworkScan()
        {
            dgv.Rows.Clear();
            rtbLog.Clear();
            totalCount = safeCount = warnCount = dangerCount = 0;
            ipToSite.Clear();
            UpdateStats();
            Log("[!] Желіні сканерлеу басталды...", ACCENT);

            await Task.Run(async () =>
            {
                try
                {
                    var localIps = new HashSet<string>(
                        Dns.GetHostEntry(Dns.GetHostName()).AddressList
                           .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                           .Select(a => a.ToString()));

                    string? myIp = localIps.FirstOrDefault();
                    if (myIp == null) { Log("[✕] Желі табылмады.", DANGER); return; }
                    string baseIp = myIp[..(myIp.LastIndexOf('.') + 1)];
                    Log($"[i] Менің IP: {myIp}  |  Желі: {baseIp}0/24", SUBTEXT);

                    // Own machine
                    string ownMac = GetOwnMac();
                    AddDevice("Өз құрылғым ★", myIp, ownMac, "Жергілікті машина", isOwn: true);

                    // ICMP sweep
                    Log("[i] ICMP ping sweep (254 хост)...", WARN);
                    var sem = new SemaphoreSlim(80);
                    var pingTasks = Enumerable.Range(1, 254).Select(async i =>
                    {
                        await sem.WaitAsync();
                        try { using var p = new Ping(); await p.SendPingAsync(baseIp + i, 120); }
                        catch { }
                        finally { sem.Release(); }
                    });
                    await Task.WhenAll(pingTasks);

                    // TCP port probe (finds ICMP-blocking devices)
                    Log("[i] TCP port probe (80,443,22,445,3389)...", WARN);
                    int[] ports = { 80, 443, 22, 445, 3389, 8080, 8888 };
                    var tcpTasks = Enumerable.Range(1, 254).SelectMany(i =>
                        ports.Select(async port =>
                        {
                            string ip = baseIp + i;
                            if (localIps.Contains(ip)) return;
                            try
                            {
                                using var tcp = new TcpClient();
                                var cts = new CancellationTokenSource(150);
                                await tcp.ConnectAsync(ip, port, cts.Token);
                                Log($"[+] TCP {ip}:{port} ашық", SAFE);
                            }
                            catch { }
                        }));
                    await Task.WhenAll(tcpTasks);
                    await Task.Delay(400);

                    // ARP table
                    Log("[i] ARP кестесі оқылуда...", WARN);
                    var arpEntries = ReadArpTable();
                    Log($"[i] ARP: {arpEntries.Count} жазба", SUBTEXT);

                    // mDNS discovery to find .local names (helps find phones, etc.)
                    Log("[i] Running mDNS discovery...", SUBTEXT);
                    var mdnsNames = await DiscoverMdns(1500);
                    foreach (var kv in mdnsNames)
                        Log($"[i] mDNS: {kv.Key} => {kv.Value}", SUBTEXT);

                    HashSet<string> processed = new();
                    foreach (var (ip, mac) in arpEntries)
                    {
                        if (localIps.Contains(ip)) continue;
                        if (ip.StartsWith("224.") || ip.StartsWith("239.") || ip == "255.255.255.255") continue;
                        if (!processed.Add(mac)) continue;

                        string hostname = ResolveHostname(ip);
                        if (mdnsNames.TryGetValue(ip, out string? mdnsName))
                            hostname = mdnsName;
                        string brand = GetBrand(mac);
                        string label = ComputeLabel(ip, hostname, brand);
                        AddDevice(label, ip, mac, brand);
                    }

                    Log($"[✓] Аяқталды. Барлығы: {totalCount} құрылғы.", SAFE);
                    this.Invoke(new Action(async () => await UpdateSiteInfo()));
                }
                catch (Exception ex) { Log("[✕] Қате: " + ex.Message, DANGER); }
            });
        }

        private string GetOwnMac()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    .Select(n => n.GetPhysicalAddress().ToString())
                    .Where(m => m.Length == 12)
                    .Select(m => string.Join(":", Enumerable.Range(0, 6).Select(i => m.Substring(i * 2, 2))))
                    .FirstOrDefault() ?? "00:00:00:00:00:00";
            }
            catch { return "00:00:00:00:00:00"; }
        }

        private List<(string ip, string mac)> ReadArpTable()
        {
            var result = new List<(string, string)>();
            try
            {
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo("arp", "-a")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                var matches = Regex.Matches(output,
                    @"(?<ip>\d+\.\d+\.\d+\.\d+)\s+(?<mac>([0-9a-f]{2}[:\-]){5}[0-9a-f]{2})",
                    RegexOptions.IgnoreCase);
                foreach (Match m in matches)
                    result.Add((m.Groups["ip"].Value,
                                m.Groups["mac"].Value.ToUpper().Replace('-', ':')));
            }
            catch { }
            return result;
        }

        private string ResolveHostname(string ip)
        {
            // Try reverse DNS first
            try
            {
                var entry = Dns.GetHostEntry(ip);
                if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != ip)
                    return entry.HostName;
            }
            catch { }

            // Try nslookup which sometimes returns a name when reverse DNS is present
            try
            {
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo("nslookup", ip)
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(1200);
                var mNs = Regex.Match(output, "Name:\\s*(.+)", RegexOptions.IgnoreCase);
                if (mNs.Success)
                {
                    string name = mNs.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(name) && !name.Equals(ip, StringComparison.OrdinalIgnoreCase))
                        return name;
                }
            }
            catch { }

            // Try NetBIOS name via nbtstat
            try
            {
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo("nbtstat", "-A " + ip)
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(1200);

                var m = Regex.Match(output, "^\\s*(.+?)\\s+<..>\\s+UNIQUE", RegexOptions.Multiline);
                if (m.Success)
                {
                    string name = m.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(name) && !name.StartsWith("MAC Address", StringComparison.OrdinalIgnoreCase))
                        return name;
                }
            }
            catch { }

            // Try ping -a which may resolve and include the hostname in output
            try
            {
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo("ping", $"-a -n 1 {ip}")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(1200);
                var mPing = Regex.Match(output, "Pinging\\s+(.+?)\\s+\\[", RegexOptions.IgnoreCase);
                if (mPing.Success)
                {
                    string name = mPing.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(name) && !name.Equals(ip, StringComparison.OrdinalIgnoreCase))
                        return name;
                }
            }
            catch { }

            return ip;
        }

        private string ComputeLabel(string ip, string hostname, string brand)
        {
            // Prefer a human-friendly hostname when available, otherwise use brand, then fall back to IP
            if (!string.IsNullOrEmpty(hostname) && hostname != ip)
            {
                // Show hostname on first line and IP on second so site monitor can still extract IP
                return hostname + "\n" + ip;
            }
            if (!string.IsNullOrEmpty(brand) && brand != "Белгісіз")
            {
                return brand + "\n" + ip;
            }
            return ip;
        }

        private void AddDevice(string label, string ip, string mac,
                               string brand = "", bool isOwn = false)
        {
            this.Invoke(new Action(() =>
            {
                totalCount++;
                bool isSafe = isOwn || whiteList.Any(w => mac.StartsWith(w, StringComparison.OrdinalIgnoreCase));
                bool isUnknown = !isOwn && (string.IsNullOrEmpty(brand) || brand == "Белгісіз");

                if (isSafe) safeCount++;
                else if (isUnknown) warnCount++;
                else dangerCount++;

                string status = isOwn ? "ӨЗІМНІҢ" : isSafe ? "ҚАУІПСІЗ" : "БӨТЕН";
                string typeIcon = isOwn ? "★ ДК" : "⬡ Құрылғы";

                int rowIdx = dgv.Rows.Add(typeIcon, label, mac,
                    string.IsNullOrEmpty(brand) ? "Белгісіз" : brand,
                    "—", status);

                var row = dgv.Rows[rowIdx];
                row.DefaultCellStyle.BackColor =
                    isOwn ? Color.FromArgb(18, 52, 25) :
                    isSafe ? Color.FromArgb(16, 46, 22) :
                    isUnknown ? Color.FromArgb(48, 38, 8) :
                                Color.FromArgb(52, 14, 14);
                row.DefaultCellStyle.ForeColor =
                    isOwn ? SAFE :
                    isSafe ? Color.FromArgb(140, 220, 140) :
                    isUnknown ? WARN : DANGER;

                row.Cells["Status"].Style.ForeColor =
                    isOwn ? SAFE : isSafe ? SAFE : isUnknown ? WARN : DANGER;
                row.Cells["Status"].Style.Font = new Font("Segoe UI Semibold", 9f);

                UpdateStats();
            }));
        }

        private string GetBrand(string mac)
        {
            if (string.IsNullOrEmpty(mac) || mac.Length < 8) return "Белгісіз";
            string p = mac.Replace(":", "").Substring(0, 6).ToUpper();
            var db = new Dictionary<string, string>
            {
                {"87BAE3","TP-Link"}, {"3C0B4F","Xiaomi"},    {"3034DB","Apple"},
                {"005056","VMware"}, {"000C29","VMware"},     {"001C42","Parallels"},
                {"F4F5D8","ASUS"},   {"74D02B","ASUS"},       {"B4EED4","ASUS"},
                {"A4C3F0","Samsung"},{"8C8D28","Samsung"},    {"FCBF97","Huawei"},
                {"286ED4","Huawei"}, {"60E32C","Lenovo"},     {"A0A4C5","Lenovo"},
                {"3C8CF8","Intel"},  {"00D0C9","D-Link"},     {"001CF0","D-Link"},
                {"E0CB4E","Netgear"},{"C45AB1","Netgear"},    {"74DA38","Raspberry Pi"},
                {"DCA632","Google"}, {"F88FCA","Google"},     {"40A36B","OnePlus"},
                {"0417F8","Xiaomi"}, {"58440E","Xiaomi"},     {"6C72E2","Realme"},
                {"C83A35","TP-Link"},{"50D4F7","TP-Link"},    {"E46F13","Xiaomi"},
                {"9C9DFF","Redmi"},  {"0C80C3","Redmi"},      {"A8A159","Apple"},
                {"F0B479","Apple"},  {"3C2EFF","Apple"},      {"B8782E","Xiaomi"},
                {"18DC56","Xiaomi"}, {"645AED","Huawei"},     {"70B3D5","Cisco"},
                {"001A2F","Cisco"},  {"B8D7AF","Cisco"},
            };
            if (db.TryGetValue(p, out string? brand)) return brand;
            return (new[] { '2', '6', 'A', 'E' }.Contains(mac[1])) ? "Private MAC" : "Белгісіз";
        }

        // ══════════════════════════════════════════════════════════════════════
        //  GEMINI AI
        // ══════════════════════════════════════════════════════════════════════
        private async Task<string> AskGemini(string prompt)
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                var body = new
                {
                    contents = new[]
                    {
                        new { parts = new[] { new {
                            text = "Сен киберқауіпсіздік маманысың. " +
                                   "Мына сұраққа қазақша нақты, қысқа жауап бер: " + prompt
                        }}}
                    }
                };
                string json = JsonConvert.SerializeObject(body);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var resp = await client.PostAsync(ApiUrl + MyGeminiKey, content);
                string resJson = await resp.Content.ReadAsStringAsync();

                if (!resp.IsSuccessStatusCode)
                    return (int)resp.StatusCode == 429
                        ? "AI: Квота бітті. 30 сек күтіңіз."
                        : $"API Қатесі: {resp.StatusCode}";

                var result = JsonConvert.DeserializeObject<JObject>(resJson);
                return result?["candidates"]?[0]?["content"]?["parts"]?[0]?["text"]
                               ?.ToString()?.Trim() ?? "Жауап бос келді.";
            }
            catch (Exception ex) { return "Байланыс қатесі: " + ex.Message; }
        }

        // ══════════════════════════════════════════════════════════════════════
        //  GRID
        // ══════════════════════════════════════════════════════════════════════
        private DataGridView BuildGrid()
        {
            var g = new DataGridView
            {
                Dock = DockStyle.Fill,
                BackgroundColor = BG,
                RowHeadersVisible = false,
                AllowUserToAddRows = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                GridColor = BG3,
                EnableHeadersVisualStyles = false
            };

            g.DefaultCellStyle.BackColor = BG;
            g.DefaultCellStyle.ForeColor = TEXT;
            g.DefaultCellStyle.SelectionBackColor = Color.FromArgb(38, 56, 84);
            g.DefaultCellStyle.SelectionForeColor = Color.White;
            g.DefaultCellStyle.Font = new Font("Segoe UI", 9f);
            g.DefaultCellStyle.Padding = new Padding(8, 6, 8, 6);

            g.ColumnHeadersDefaultCellStyle.BackColor = BG3;
            g.ColumnHeadersDefaultCellStyle.ForeColor = SUBTEXT;
            g.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 8.5f);
            g.ColumnHeadersDefaultCellStyle.Padding = new Padding(8, 8, 8, 8);
            g.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            g.ColumnHeadersHeight = 38;
            g.RowTemplate.Height = 50;

            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "Type", HeaderText = "ТҮР", FillWeight = 70 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "Info", HeaderText = "IP / ХОСТ", FillWeight = 155 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "MAC", HeaderText = "MAC", FillWeight = 125 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "Brand", HeaderText = "ӨНДІРУШІ", FillWeight = 95 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "Sites", HeaderText = "🌐 САЙТТАР", FillWeight = 210 });
            g.Columns.Add(new DataGridViewTextBoxColumn { Name = "Status", HeaderText = "СТАТУС", FillWeight = 85 });

            g.Columns["Sites"].DefaultCellStyle.ForeColor = Color.FromArgb(100, 180, 255);
            g.Columns["Sites"].DefaultCellStyle.Font = new Font("Segoe UI", 8.5f);

            return g;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  HELPERS
        // ══════════════════════════════════════════════════════════════════════
        private Label MakeStatCard(Control parent, string title, Color color)
        {
            var p = new Panel { Size = new Size(195, 58), Margin = new Padding(0, 0, 10, 0), BackColor = BG3 };
            var bar = new Panel { Location = new Point(0, 0), Size = new Size(3, 58), BackColor = color };
            var val = new Label { Text = "0", ForeColor = color, Font = new Font("Segoe UI Semibold", 20f), Location = new Point(14, 2), AutoSize = true };
            var lbl = new Label { Text = title, ForeColor = SUBTEXT, Font = new Font("Segoe UI", 7.5f), Location = new Point(15, 38), AutoSize = true };
            p.Controls.Add(bar); p.Controls.Add(val); p.Controls.Add(lbl);
            parent.Controls.Add(p);
            return val;
        }

        private Button MakeDockBtn(string text, Color bg)
        {
            var btn = new Button
            {
                Text = text,
                Size = new Size(182, 44),
                Margin = new Padding(0, 0, 0, 8),
                BackColor = bg,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI Semibold", 9f),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 0;
            return btn;
        }

        private void Log(string msg, Color color)
        {
            Action act = () => { rtbLog.SelectionColor = color; rtbLog.AppendText(msg + "\n"); rtbLog.ScrollToCaret(); };
            if (rtbLog.InvokeRequired) rtbLog.Invoke(act); else act();
        }

        private void UpdateStats()
        {
            Action act = () =>
            {
                lblTotal.Text = totalCount.ToString();
                lblSafe.Text = safeCount.ToString();
                lblWarn.Text = warnCount.ToString();
                lblDanger.Text = dangerCount.ToString();
            };
            if (lblTotal.InvokeRequired) this.Invoke(act); else act();
        }

        private void ExportData()
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("WIFIWATCH IDS — Желі есебі");
                sb.AppendLine(new string('═', 80));
                foreach (DataGridViewRow r in dgv.Rows)
                    sb.AppendLine($"{r.Cells["Info"].Value,-30} | {r.Cells["MAC"].Value,-20} | " +
                                  $"{r.Cells["Brand"].Value,-16} | {r.Cells["Sites"].Value,-30} | {r.Cells["Status"].Value}");
                File.WriteAllText("NetworkReport.txt", sb.ToString(), Encoding.UTF8);
                MessageBox.Show("Есеп NetworkReport.txt файлына сақталды!", "Есеп",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex) { MessageBox.Show("Қате: " + ex.Message); }
        }
    }
}