using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace TunnelGuard;

internal sealed class GuardApp : ApplicationContext
{
    private static readonly Color Ink = Color.FromArgb(25, 36, 58);
    private static readonly Color Muted = Color.FromArgb(71, 88, 112);
    private readonly Form window = new();
    private readonly Label heading = new();
    private readonly Label description = new();
    private readonly Label actionResult = new();
    private readonly Button switchButton = new();
    private readonly ToolStripMenuItem traySwitch = new();
    private readonly NotifyIcon tray = new();
    private readonly TextBox client = new();
    private readonly TextBox adapter = new();
    private readonly NumericUpDown port = new() { Minimum = 1, Maximum = 65529, Width = 100 };
    private readonly ListBox rules = new();
    private readonly ComboBox ruleType = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 140 };
    private readonly TextBox ruleValue = new();
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 6000 };
    private readonly bool repair;
    private Icon? currentIcon;
    private Color iconColor;
    private Settings settings;
    private RoutingFile? routing;
    private string state = "Unknown";
    private bool reading;
    private bool working;
    private bool quitting;

    public GuardApp(bool repair)
    {
        this.repair = repair;
        settings = GuardBackend.LoadSettings();
        BuildWindow();
        BuildTray();
        SetPresentation();
        timer.Tick += async (_, _) => await Refresh();
        window.Shown += async (_, _) => await Initialize();
        window.Show();
        timer.Start();
    }

    private void BuildWindow()
    {
        window.Text = "Tunnel Guard";
        window.Font = new Font("Segoe UI", 10);
        window.StartPosition = FormStartPosition.CenterScreen;
        window.ClientSize = new Size(690, 504);
        window.MinimumSize = new Size(650, 510);
        window.BackColor = Color.FromArgb(242, 245, 250);
        window.ForeColor = Ink;
        window.Padding = new Padding(18);
        window.FormClosing += (_, args) =>
        {
            if (args.CloseReason != CloseReason.UserClosing || quitting)
                return;
            args.Cancel = true;
            window.Hide();
        };

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildProtection());
        tabs.TabPages.Add(BuildRouting());
        tabs.TabPages.Add(BuildSettings());
        window.Controls.Add(tabs);
    }

    private TabPage BuildProtection()
    {
        var page = new TabPage("Защита") { BackColor = Color.White };
        var column = Column();
        heading.AutoSize = true;
        heading.Font = new Font("Segoe UI", 24, FontStyle.Bold);
        heading.ForeColor = Ink;
        description.ForeColor = Muted;
        description.MaximumSize = new Size(550, 0);
        description.AutoSize = true;
        actionResult.ForeColor = Muted;
        actionResult.MaximumSize = new Size(550, 0);
        actionResult.AutoSize = true;

        switchButton.AutoSize = true;
        switchButton.Padding = new Padding(15, 6, 15, 6);
        switchButton.BackColor = Color.FromArgb(36, 76, 170);
        switchButton.ForeColor = Color.White;
        switchButton.FlatStyle = FlatStyle.Flat;
        switchButton.FlatAppearance.BorderSize = 0;
        switchButton.Click += async (_, _) => await Toggle();
        var vpn = Button("Открыть v2rayN", OpenClient);
        var row = Row();
        row.Controls.AddRange([switchButton, vpn]);
        column.Controls.AddRange([heading, description, row, actionResult]);
        page.Controls.Add(column);
        return page;
    }

    private TabPage BuildSettings()
    {
        var page = new TabPage("Подключение") { BackColor = Color.White };
        var column = Column();
        var info = Copy("Выбери установленный v2rayN с ядром Mihomo и включи режим TUN. Сначала импортируй свой профиль в v2rayN.");
        client.Width = 460;
        client.Text = settings.ClientPath;
        adapter.Width = 250;
        adapter.Text = settings.Adapter;
        port.Value = Math.Clamp(settings.ProxyPort, 1, 65529);
        var clientRow = Row();
        clientRow.Controls.AddRange([client, Button("Обзор…", () => ChooseExe(client, "Выбери v2rayN.exe"))]);
        column.Controls.AddRange([info, Copy("Исполняемый файл v2rayN"), clientRow, Copy("Имя адаптера TUN"), adapter,
            Copy("Порт локального прокси"), port, Button("Сохранить подключение", SaveSettings)]);
        page.Controls.Add(column);
        return page;
    }

    private TabPage BuildRouting()
    {
        var page = new TabPage("Обход VPN") { BackColor = Color.White };
        var column = Column();
        ruleType.Items.AddRange(["Домен", "Имя процесса", "Путь к .exe"]);
        ruleType.SelectedIndex = 0;
        ruleValue.Width = 290;
        ruleValue.PlaceholderText = "example.org";
        var browse = Button("Выбрать .exe", () => ChooseExe(ruleValue, "Выбери программу для обхода"));
        browse.Visible = false;
        ruleType.SelectedIndexChanged += (_, _) =>
        {
            browse.Visible = ruleType.SelectedIndex == 2;
            ruleValue.PlaceholderText = ruleType.SelectedIndex switch
            {
                0 => "example.org", 1 => "program.exe", _ => @"C:\Folder\program.exe"
            };
        };
        var addRow = Row();
        addRow.Controls.AddRange([ruleType, ruleValue, browse, Button("Добавить", AddRule)]);
        addRow.WrapContents = true;
        addRow.Width = 610;
        rules.Width = 590;
        rules.Height = 175;
        rules.HorizontalScrollbar = true;
        var actions = Row();
        actions.Controls.AddRange([Button("Сохранить правила", SaveRoutes), Button("Удалить выбранное", RemoveRule),
            Button("Перечитать", LoadRoutes)]);
        column.Controls.AddRange([Copy("Сайты и приложения в этом списке используют прямое подключение, пока работает Mihomo."),
            addRow, rules, actions]);
        page.Controls.Add(column);
        return page;
    }

    private void BuildTray()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Открыть Tunnel Guard", null, (_, _) => ShowWindow());
        traySwitch.Click += async (_, _) => await Toggle();
        menu.Items.Add(traySwitch);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Закрыть панель", null, (_, _) =>
        {
            if (working)
                return;
            quitting = true;
            ExitThread();
            window.Close();
        });
        tray.ContextMenuStrip = menu;
        tray.MouseClick += (_, args) => { if (args.Button == MouseButtons.Left) ShowWindow(); };
        tray.Visible = true;
    }

    private async Task Initialize()
    {
        await Refresh();
        LoadRoutes(showErrors: false);
        if (repair && state == "LegacyInactive")
            await Apply("CleanLegacy");
    }

    private async Task Refresh()
    {
        if (reading || working)
            return;
        reading = true;
        try
        {
            state = await GuardBackend.Run("Status");
        }
        catch (Exception exception)
        {
            state = "Unknown";
            actionResult.Text = exception.Message;
        }
        finally
        {
            reading = false;
            SetPresentation();
        }
    }

    private void SetPresentation()
    {
        bool tunnel = NetworkInterface.GetAllNetworkInterfaces().Any(n =>
            string.Equals(n.Name, settings.Adapter, StringComparison.OrdinalIgnoreCase) &&
            n.OperationalStatus == OperationalStatus.Up);
        (string title, string detail, Color color) = state switch
        {
            "On" when tunnel => ("Защита включена", "Адаптер TUN активен. Windows разрешает обычным приложениям выход через туннель.", Color.SeaGreen),
            "On" => ("Интернет заблокирован", "Защита включена. Чтобы вернуть доступ, подключи VPN в режиме TUN.", Color.DarkOrange),
            "Off" => ("Защита выключена", "Windows использует обычные правила доступа. При отключённом VPN возможен прямой выход.", Color.SlateGray),
            "LegacyInactive" => ("Защита выключена", "Остались правила от предыдущего переключателя. Их можно удалить здесь.", Color.SlateGray),
            "LegacyActive" => ("Найдена старая защита", "Восстанови прежние правила старым переключателем перед переходом на Tunnel Guard.", Color.DarkOrange),
            "Partial" => ("Проверь правила Windows", "Изменение завершилось частично. Восстанови предыдущие настройки.", Color.DarkOrange),
            _ => ("Проверяем защиту", "Статус брандмауэра пока недоступен.", Color.SlateGray)
        };
        heading.Text = title;
        description.Text = detail;
        string action = state switch
        {
            "On" => "Выключить защиту",
            "Partial" => "Восстановить правила",
            "LegacyInactive" => "Удалить старые правила",
            _ => "Включить защиту"
        };
        switchButton.Text = working ? "Применяем правила…" : action;
        switchButton.Enabled = !working && !reading && state is "On" or "Off" or "Partial" or "LegacyInactive";
        traySwitch.Text = action;
        traySwitch.Enabled = switchButton.Enabled;
        tray.Text = $"Tunnel Guard · {title}";
        if (currentIcon is null || iconColor != color)
        {
            var next = MakeIcon(color);
            tray.Icon = next;
            window.Icon = next;
            currentIcon?.Dispose();
            currentIcon = next;
            iconColor = color;
        }
    }

    private async Task Toggle()
    {
        if (!switchButton.Enabled)
            return;
        if (state == "LegacyInactive")
        {
            await Apply("CleanLegacy");
            return;
        }
        if (state == "Off" && !File.Exists(settings.ClientPath))
        {
            Notify("Сначала укажи v2rayN на вкладке «Подключение».");
            return;
        }
        if (state is "On" or "Partial")
        {
            if (MessageBox.Show(window, "После восстановления прежних правил приложения снова смогут выходить напрямую при отключении VPN.",
                    "Выключить защиту?", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2)
                == DialogResult.Yes)
                await Apply("Disable");
            return;
        }
        await Apply("Enable");
    }

    private async Task Apply(string action)
    {
        working = true;
        actionResult.Text = "";
        SetPresentation();
        try
        {
            await GuardBackend.Run(action);
            actionResult.Text = action == "Enable"
                ? "Проверено: через VPN HTTPS работает, прямое тестовое соединение заблокировано."
                : "Правила Windows обновлены.";
        }
        catch (Exception exception)
        {
            actionResult.Text = "Windows не завершила действие. " + exception.Message;
            if (!window.Visible)
            {
                tray.BalloonTipTitle = "Tunnel Guard";
                tray.BalloonTipText = "Windows не завершила изменение. Открой панель для подробностей.";
                tray.ShowBalloonTip(5000);
            }
        }
        finally
        {
            working = false;
            await Refresh();
        }
    }

    private void SaveSettings()
    {
        if (state != "Off" || working)
        {
            Notify("Измени подключение, когда защита выключена.");
            return;
        }
        if (!File.Exists(client.Text) || !Path.GetFileName(client.Text).Equals("v2rayN.exe", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(adapter.Text))
        {
            Notify("Укажи существующий v2rayN.exe и имя его адаптера TUN.");
            return;
        }
        TryUi(() =>
        {
            settings = new Settings(Path.GetFullPath(client.Text), adapter.Text.Trim(), (int)port.Value);
            GuardBackend.SaveSettings(settings);
            LoadRoutes(showErrors: false);
            SetPresentation();
            Notify("Подключение сохранено.");
        });
    }

    private void OpenClient() => TryUi(() =>
    {
        if (!File.Exists(settings.ClientPath))
            throw new InvalidOperationException("Укажи v2rayN на вкладке «Подключение».");
        Process.Start(new ProcessStartInfo(settings.ClientPath)
        {
            UseShellExecute = true,
            WorkingDirectory = Path.GetDirectoryName(settings.ClientPath)!
        })?.Dispose();
    });

    private void LoadRoutes() => LoadRoutes(showErrors: true);

    private void LoadRoutes(bool showErrors)
    {
        try
        {
            var next = new RoutingFile(settings);
            string[] list = next.ReadRules();
            rules.Items.Clear();
            rules.Items.AddRange(list);
            routing = next;
        }
        catch (Exception exception)
        {
            routing = null;
            rules.Items.Clear();
            if (showErrors)
                Notify(exception.Message);
        }
    }

    private void AddRule()
    {
        if (routing is null)
        {
            Notify("Сначала укажи клиент с файлом Mixin.yaml.");
            return;
        }
        string value = ruleValue.Text.Trim();
        string type = ruleType.SelectedIndex switch { 0 => "DOMAIN-SUFFIX", 1 => "PROCESS-NAME", _ => "PROCESS-PATH" };
        bool valid = !value.Contains(',') && !value.Any(char.IsControl) && (ruleType.SelectedIndex switch
        {
            0 => Uri.CheckHostName(value) == UriHostNameType.Dns && value.Contains('.') && !value.Contains('*'),
            1 => value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && value.IndexOfAny(Path.GetInvalidFileNameChars()) < 0,
            _ => Path.IsPathFullyQualified(value) && File.Exists(value) && value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
        });
        if (!valid)
        {
            Notify("Укажи домен без URL, имя .exe или полный путь к программе.");
            return;
        }
        string rule = $"{type},{value},DIRECT";
        if (!rules.Items.Contains(rule))
            rules.Items.Add(rule);
        ruleValue.Clear();
    }

    private void RemoveRule()
    {
        if (rules.SelectedIndex >= 0)
            rules.Items.RemoveAt(rules.SelectedIndex);
    }

    private void SaveRoutes() => TryUi(() =>
    {
        if (routing is null)
            throw new InvalidOperationException("Сначала открой файл правил.");
        if (MessageBox.Show(window, "Правила DIRECT разрешают выбранному трафику идти мимо VPN. Сохранить список?",
                "Правила обхода", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;
        routing.Save(rules.Items.Cast<string>().ToArray());
        LoadRoutes();
        Notify("Правила сохранены. Перезапусти v2rayN, чтобы применить их.");
    });

    private void ShowWindow()
    {
        window.Show();
        if (window.WindowState == FormWindowState.Minimized)
            window.WindowState = FormWindowState.Normal;
        window.Activate();
    }

    private void Notify(string message) =>
        MessageBox.Show(window, message, "Tunnel Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);

    private void TryUi(Action action)
    {
        try { action(); }
        catch (Exception exception) { Notify(exception.Message); }
    }

    private static void ChooseExe(TextBox target, string title)
    {
        using var dialog = new OpenFileDialog { Title = title, Filter = "Программы (*.exe)|*.exe", CheckFileExists = true };
        if (dialog.ShowDialog() == DialogResult.OK)
            target.Text = dialog.FileName;
    }

    private static Label Copy(string text) =>
        new() { Text = text, ForeColor = Muted, AutoSize = true, MaximumSize = new Size(570, 0), Margin = new Padding(3, 6, 3, 6) };

    private static FlowLayoutPanel Column() =>
        new() { Dock = DockStyle.Fill, Padding = new Padding(20), FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };

    private static FlowLayoutPanel Row() =>
        new() { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = false, Margin = new Padding(0, 8, 0, 8) };

    private static Button Button(string title, Action handler)
    {
        var button = new Button { Text = title, AutoSize = true, Padding = new Padding(6, 3, 6, 3) };
        button.Click += (_, _) => handler();
        return button;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);

    private static Icon MakeIcon(Color color)
    {
        using var image = new Bitmap(32, 32);
        using var graphics = Graphics.FromImage(image);
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using var brush = new SolidBrush(color);
        graphics.FillPolygon(brush, [new Point(16, 2), new(29, 7), new(27, 19), new(23, 25), new(16, 30), new(9, 25), new(5, 19), new(3, 7)]);
        using var pen = new Pen(Color.White, 2.5f);
        graphics.DrawLines(pen, [new Point(10, 16), new(14, 20), new(22, 11)]);
        IntPtr handle = image.GetHicon();
        try { return (Icon)Icon.FromHandle(handle).Clone(); }
        finally { DestroyIcon(handle); }
    }

    protected override void ExitThreadCore()
    {
        timer.Dispose();
        tray.Visible = false;
        tray.ContextMenuStrip?.Dispose();
        tray.Dispose();
        currentIcon?.Dispose();
        base.ExitThreadCore();
    }
}
