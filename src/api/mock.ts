// In-memory stand-in for the Rust backend. Loaded only by the dev server (or `vite build --mode mock`)
// when the page is not running inside Tauri. Never touches the real system.
import type { Transport } from "./backend";
import type {
  Check,
  CheckId,
  CheckStatus,
  ClientDetection,
  ConfigSnapshot,
  CoreInfo,
  CoreRulesState,
  Diagnosis,
  EventMap,
  GuardState,
  Outcome,
  ProcessGroup,
  ProcessGroupsConfig,
  ProcessInfo,
  ProgressStage,
  ProtectionAction,
  Settings,
  Status,
} from "./types";

export const scenarios = {
  on: "Защита включена, всё готово",
  "off-ready": "Защита выключена, всё готово",
  "off-not-ready": "Защита выключена, v2rayN не запущен",
  "tun-down": "Защита включена, TUN-адаптер упал",
  partial: "Правила применены частично",
  "legacy-inactive": "Остались правила старой версии",
  unconfigured: "Подключение не настроено",
  "rules-pending": "Правила сохранены, но не применены в ядре",
  "enable-fails": "Включение падает на проверке",
  "uac-cancel": "Запрос администратора отменён",
  draft: "Есть несохранённый черновик правил",
  slow: "Медленный бэкенд",
} as const;

export type ScenarioName = keyof typeof scenarios;

const v2raynPath = "C:\\Tools\\v2rayN\\v2rayN.exe";
const sampleRules = [
  "DOMAIN-SUFFIX,youtube.com,PROXY",
  "DOMAIN-SUFFIX,gosuslugi.ru,DIRECT",
  "PROCESS-NAME,Telegram.exe,PROXY",
  "PROCESS-PATH,C:\\Games\\Steam\\steam.exe,DIRECT",
  "DOMAIN-SUFFIX,doubleclick.net,REJECT",
];
const servers = ["NL-Amsterdam-02", "DE-Frankfurt-01", "FI-Helsinki-03"];
const sampleGroups: ProcessGroup[] = [
  {
    id: "work-browser",
    title: "Рабочий браузер",
    selectors: [
      { kind: "name", value: "firefox.exe" },
      { kind: "argument", image: "firefox.exe", value: "-P work" },
    ],
    includes: [],
  },
  {
    id: "messengers",
    title: "Мессенджеры",
    selectors: [
      { kind: "name", value: "Telegram.exe" },
      { kind: "package_family", value: "5319275A.WhatsAppDesktop_cv1g1gvanyjgm" },
      { kind: "service", value: "ExampleSyncService" },
    ],
    includes: [],
  },
  { id: "all-work", title: "Всё рабочее", selectors: [], includes: ["work-browser", "messengers"] },
];

type Failure = { stage: ProgressStage; error: string };

type World = {
  protection: GuardState;
  settings: Settings;
  clientRunning: boolean;
  coreRunning: boolean;
  tunEnabled: boolean;
  mode: string;
  mixin: boolean;
  rules: string[];
  /** Rules the running core uses; `null` = the generated config could not be recognised. */
  coreRules: string[] | null;
  groups: ProcessGroup[];
  draft: string[] | null;
  enableFailure: Failure | null;
  speed: number;
  busy: boolean;
  activeServer: string;
};

const messages = {
  notReady:
    "Туннель Mihomo ещё не готов. Подключи профиль в v2rayN, включи Enable TUN в режиме Rule и повтори. Если ошибка осталась, проверь имя адаптера и порт во вкладке «Подключение».",
  verify: "Проверка связи не прошла. Проверь соединение через VPN и фактическое состояние защиты.",
  uac: "Запрос администратора отменён. Правила остались прежними.",
  busy: "Tunnel Guard уже меняет настройки. Повтори после завершения операции.",
  settings: "Проверь путь к v2rayN, имя TUN-адаптера и порт прокси во вкладке «Подключение».",
};

function baseWorld(): World {
  return {
    protection: "On",
    settings: { client_path: v2raynPath, adapter: "Mihomo", proxy_port: 10808 },
    clientRunning: true,
    coreRunning: true,
    tunEnabled: true,
    mode: "rule",
    mixin: true,
    rules: [...sampleRules],
    coreRules: [...sampleRules],
    groups: structuredClone(sampleGroups),
    draft: null,
    enableFailure: null,
    speed: 1,
    busy: false,
    activeServer: servers[0] ?? "",
  };
}

function scenarioWorld(name: ScenarioName): World {
  const world = baseWorld();
  switch (name) {
    case "on":
      break;
    case "off-ready":
      world.protection = "Off";
      break;
    case "off-not-ready":
      Object.assign(world, {
        protection: "Off",
        clientRunning: false,
        coreRunning: false,
        tunEnabled: false,
      });
      break;
    case "tun-down":
      world.tunEnabled = false;
      break;
    case "partial":
      world.protection = "Partial";
      break;
    case "legacy-inactive":
      world.protection = "LegacyInactive";
      break;
    case "unconfigured":
      world.protection = "Off";
      world.settings = { client_path: "", adapter: "Mihomo", proxy_port: 10808 };
      world.rules = [];
      world.coreRules = [];
      world.groups = [];
      break;
    case "rules-pending":
      world.rules = [...sampleRules, "DOMAIN-SUFFIX,chatgpt.com,PROXY"];
      break;
    case "enable-fails":
      world.protection = "Off";
      world.enableFailure = { stage: "verify", error: messages.verify };
      break;
    case "uac-cancel":
      world.protection = "Off";
      world.enableFailure = { stage: "elevate", error: messages.uac };
      break;
    case "draft":
      world.draft = [...sampleRules.slice(0, 3), "DOMAIN-SUFFIX,github.com,PROXY", "MATCH,DIRECT"];
      break;
    case "slow":
      world.protection = "Off";
      world.speed = 3;
      break;
  }
  return world;
}

const equal = (left: unknown, right: unknown) => JSON.stringify(left) === JSON.stringify(right);

function readScenario(): ScenarioName {
  const requested = new URLSearchParams(window.location.search).get("mock");
  if (requested && requested in scenarios) return requested as ScenarioName;
  if (requested) console.warn(`[mock] неизвестный сценарий «${requested}», использую «on»`);
  return "on";
}

type Handler = (payload: unknown) => void;

export class MockBackend {
  readonly scenario: ScenarioName;
  private world: World;
  private handlers = new Map<string, Set<Handler>>();
  private visible = true;
  private pollTimer: number | undefined;
  private pickCount = 0;

  constructor(scenario: ScenarioName) {
    this.scenario = scenario;
    this.world = scenarioWorld(scenario);
    this.schedulePoll();
  }

  // ---------- transport ----------

  invoke = async (command: string, args: Record<string, unknown> = {}): Promise<unknown> => {
    const handler = this.commands[command];
    if (!handler) throw new Error(`Команда ${command} не найдена в mock-бэкенде.`);
    const result = await handler(args);
    console.debug(`[mock] ${command}`, args, "→", result);
    return result;
  };

  listen = (event: string, handler: Handler): Promise<() => void> => {
    let set = this.handlers.get(event);
    if (!set) this.handlers.set(event, (set = new Set()));
    set.add(handler);
    return Promise.resolve(() => set.delete(handler));
  };

  // ---------- dev switcher hooks ----------

  /** Simulates another program (guardctl, a text editor) editing the saved rules. */
  externalRulesEdit() {
    const added = "DOMAIN-SUFFIX,example.org,DIRECT";
    const rules = this.world.rules.filter((rule) => rule !== added);
    rules.splice(rules.at(-1) === "MATCH,DIRECT" ? rules.length - 1 : rules.length, 0, added);
    this.world.rules = rules;
    this.emit("guard-config", this.snapshot());
  }

  /** Toggles the VPN core as if the user stopped/started the profile in v2rayN. */
  toggleVpn() {
    const up = !(this.world.coreRunning && this.world.tunEnabled);
    Object.assign(this.world, { clientRunning: up, coreRunning: up, tunEnabled: up });
    this.emit("guard-state", this.status());
  }

  // ---------- internals ----------

  private emit<E extends keyof EventMap>(event: E, payload: EventMap[E]) {
    for (const handler of this.handlers.get(event) ?? []) window.setTimeout(() => handler(payload), 0);
  }

  private wait(ms: number) {
    return new Promise<void>((resolve) => window.setTimeout(resolve, ms * this.world.speed));
  }

  private schedulePoll() {
    window.clearTimeout(this.pollTimer);
    this.pollTimer = window.setTimeout(
      () => {
        this.emit("guard-state", this.status());
        this.schedulePoll();
      },
      this.visible ? 4000 : 20000,
    );
  }

  private tunUp() {
    const w = this.world;
    return w.clientRunning && w.coreRunning && w.tunEnabled;
  }

  private status(): Status {
    return { state: this.world.protection, adapter_up: this.tunUp(), checked_at: Date.now() };
  }

  private snapshot(): ConfigSnapshot {
    return {
      settings: { ...this.world.settings },
      rules: this.world.settings.client_path ? [...this.world.rules] : null,
    };
  }

  private clientValid() {
    return this.world.settings.client_path.toLowerCase().endsWith("\\v2rayn.exe");
  }

  private diagnosis(): Diagnosis {
    const w = this.world;
    const port = w.settings.proxy_port;
    const results: Array<[CheckId, CheckStatus, string | null]> = [];
    const add = (id: CheckId, status: CheckStatus, detail: string | null) =>
      results.push([id, status, detail]);
    const client = this.clientValid();
    add(
      "client",
      client ? "ok" : "fail",
      client ? null : w.settings.client_path ? "файл не найден" : "путь не указан",
    );
    add("core", client ? "ok" : "skip", client ? "bin\\mihomo\\mihomo.exe" : null);
    add(
      "mixin",
      client ? (w.mixin ? "ok" : "warn") : "skip",
      client ? `EnableMixinContent=${w.mixin}` : null,
    );
    add(
      "client_running",
      w.clientRunning ? "ok" : "fail",
      w.clientRunning ? "PID 8412" : "процесс не найден",
    );
    add("proxy", w.coreRunning ? "ok" : "fail", w.coreRunning ? `порт ${port}` : `порт ${port} не слушается`);
    const controller = w.coreRunning;
    add("controller", controller ? "ok" : "skip", controller ? `порт ${port + 6}` : null);
    add(
      "adapter",
      this.tunUp() ? "ok" : "fail",
      this.tunUp() ? `${w.settings.adapter}: Up` : `адаптер ${w.settings.adapter} не найден`,
    );
    add(
      "tun",
      controller ? (w.tunEnabled ? "ok" : "fail") : "skip",
      controller ? (w.tunEnabled ? `tun.device=${w.settings.adapter}` : "tun.enable=false") : null,
    );
    add(
      "mode",
      controller ? (w.mode === "rule" ? "ok" : "fail") : "skip",
      controller ? `mode=${w.mode}` : null,
    );
    const checks: Check[] = results.map(([id, status, detail]) => ({ id, status, detail }));
    const ready = checks.every(
      (check) => check.id === "mixin" || check.id === "client_running" || check.status === "ok",
    );
    const core: CoreInfo | null = controller
      ? {
          version: "v1.19.15",
          mode: w.mode,
          tun_enabled: w.tunEnabled,
          tun_device: w.tunEnabled ? w.settings.adapter : null,
          groups: [
            { name: "PROXY", kind: "Selector", now: "auto" },
            { name: "auto", kind: "URLTest", now: w.activeServer },
          ],
        }
      : null;
    return { checks, ready, core, checked_at: Date.now() };
  }

  private coreRules(): CoreRulesState {
    const w = this.world;
    if (!w.coreRunning) return { state: "unknown", detail: "Mihomo не запущен — сравнивать не с чем." };
    if (!w.coreRules) return { state: "unknown", detail: "Конфигурация, созданная v2rayN, не распознана." };
    return equal(w.coreRules, w.rules)
      ? { state: "applied", detail: null }
      : { state: "pending", detail: null };
  }

  private async runProtection(action: ProtectionAction) {
    const w = this.world;
    if (w.busy) throw new Error(messages.busy);
    w.busy = true;
    const stages: Array<[ProgressStage, number]> =
      action === "enable"
        ? [
            ["preflight", 900],
            ["elevate", 1600],
            ["settings", 300],
            ["tun", 500],
            ["egress", 700],
            ["backup", 600],
            ["apply", 1100],
            ["policy", 2500],
            ["verify", 2200],
          ]
        : action === "disable"
          ? [
              ["elevate", 1600],
              ["restore", 900],
              ["policy", 2500],
            ]
          : [
              ["elevate", 1600],
              ["cleanup", 1000],
              ["policy", 2500],
            ];
    const progress = (stage: ProgressStage) => this.emit("guard-progress", { action, stage, at: Date.now() });
    try {
      for (const [stage, duration] of stages) {
        progress(stage);
        await this.wait(duration);
        if (action !== "enable") continue;
        if (stage === "preflight" && !w.settings.client_path) throw new Error(messages.settings);
        if (stage === "preflight" && !this.diagnosis().ready) throw new Error(messages.notReady);
        if (w.enableFailure?.stage === stage) throw new Error(w.enableFailure.error);
      }
      w.protection = action === "enable" ? "On" : "Off";
      progress("done");
    } catch (error) {
      progress("failed");
      throw error;
    } finally {
      w.busy = false;
      this.emit("guard-state", this.status());
    }
  }

  private processes(group: ProcessGroup, seen = new Set<string>()): ProcessInfo[] {
    if (seen.has(group.id)) return [];
    seen.add(group.id);
    const own = group.selectors
      .filter((selector) => selector.kind !== "service")
      .flatMap((selector, index) => {
        const name =
          selector.kind === "argument"
            ? (selector.image ?? "program.exe")
            : selector.kind === "package_family"
              ? "WhatsApp.exe"
              : (selector.value.split("\\").pop() ?? selector.value);
        const base = 4000 + group.id.length * 97 + index * 211;
        return [
          { pid: base, name, owned: true },
          { pid: base + 12, name, owned: index !== 1 },
        ];
      });
    const nested = group.includes.flatMap((id) => {
      const child = this.world.groups.find((item) => item.id === id);
      return child ? this.processes(child, seen) : [];
    });
    return [...own, ...nested];
  }

  private services(group: ProcessGroup, seen = new Set<string>()): string[] {
    if (seen.has(group.id)) return [];
    seen.add(group.id);
    return [
      ...group.selectors.filter((selector) => selector.kind === "service").map((selector) => selector.value),
      ...group.includes.flatMap((id) => {
        const child = this.world.groups.find((item) => item.id === id);
        return child ? this.services(child, seen) : [];
      }),
    ];
  }

  private commands: Record<string, (args: Record<string, unknown>) => Promise<unknown>> = {
    load_settings: async () => {
      await this.wait(200);
      return { ...this.world.settings };
    },
    save_settings: async (args) => {
      await this.wait(700);
      const { settings, original } = args as { settings: Settings; original: Settings };
      const w = this.world;
      if (!equal(original, w.settings))
        throw new Error("Подключение изменилось в другой программе. Перечитай настройки.");
      if (equal(settings, w.settings)) return null;
      if (w.protection !== "Off" && w.protection !== "LegacyInactive")
        throw new Error("Сначала выключи защиту.");
      if (!settings.client_path.toLowerCase().endsWith("v2rayn.exe")) {
        throw new Error("Выбери существующий исполняемый файл v2rayN.exe.");
      }
      if (!settings.adapter.trim() || settings.proxy_port < 1 || settings.proxy_port > 65529) {
        throw new Error("Проверь имя TUN-адаптера и порт прокси.");
      }
      w.settings = { ...settings };
      this.emit("guard-config", this.snapshot());
      return null;
    },
    config_snapshot: async () => {
      await this.wait(300);
      return this.snapshot();
    },
    recover_routing_draft: async () => {
      await this.wait(200);
      const draft = this.world.draft;
      this.world.draft = null;
      return draft;
    },
    load_rules: async () => {
      await this.wait(300);
      return [...this.world.rules];
    },
    save_rules: async (args) => {
      await this.wait(900);
      const { rules, original, settings } = args as {
        rules: string[];
        original: string[];
        settings: Settings;
      };
      const w = this.world;
      if (!equal(settings, w.settings))
        throw new Error("Подключение изменилось в другой программе. Перечитай правила.");
      if (!equal(original, w.rules))
        throw new Error("Список изменился в другой программе. Обнови правила и повтори.");
      if (!w.mixin) throw new Error("Включи Enable Mixin Content в настройках Mihomo в v2rayN.");
      const match = rules.findIndex((rule) => rule.startsWith("MATCH,"));
      if (match >= 0 && match !== rules.length - 1) {
        throw new Error("Маршрут по умолчанию должен быть единственным и стоять последним.");
      }
      if (
        match >= 0 &&
        !rules.some((rule) => !rule.startsWith("MATCH,") && !/,(DIRECT|REJECT)$/.test(rule))
      ) {
        throw new Error("Сначала добавь хотя бы один сайт или программу с маршрутом через VPN.");
      }
      w.rules = [...rules];
      this.emit("guard-config", this.snapshot());
      return null;
    },
    vpn_targets: async () => {
      await this.wait(500);
      if (!this.world.coreRunning) throw new Error("Mihomo не отвечает. Запусти профиль в v2rayN.");
      return ["PROXY", "auto", ...servers];
    },
    pick_exe: async () => {
      await this.wait(900);
      this.pickCount += 1;
      return this.pickCount % 2 ? v2raynPath : "C:\\Program Files\\Example\\example.exe";
    },
    open_client: async () => {
      await this.wait(500);
      const w = this.world;
      if (!this.clientValid()) throw new Error("Выбери существующий исполняемый файл v2rayN.exe.");
      if (!w.clientRunning) {
        window.setTimeout(() => {
          Object.assign(w, { clientRunning: true, coreRunning: true, tunEnabled: true, mode: "rule" });
          this.emit("guard-state", this.status());
        }, 2500 * w.speed);
      }
      return null;
    },
    load_process_groups: async () => {
      await this.wait(300);
      return structuredClone({ groups: this.world.groups });
    },
    save_process_groups: async (args) => {
      await this.wait(600);
      const { config, original } = args as { config: ProcessGroupsConfig; original: ProcessGroupsConfig };
      if (!equal(original.groups, this.world.groups)) {
        throw new Error("Группы уже изменились в другой программе. Перечитай список.");
      }
      const ids = new Set<string>();
      for (const group of config.groups) {
        if (!group.title.trim() || ids.has(group.id)) {
          throw new Error("У каждой группы должны быть уникальный ID и название.");
        }
        ids.add(group.id);
        if (!group.selectors.length && !group.includes.length)
          throw new Error(`В группе «${group.id}» нет условий поиска.`);
      }
      this.world.groups = structuredClone(config.groups);
      return null;
    },
    run_process_group: async (args) => {
      const { id, stop, original } = args as { id: string; stop: boolean; original: ProcessGroupsConfig };
      await this.wait(stop ? 2200 : 900);
      if (!equal(original.groups, this.world.groups)) {
        throw new Error("Группы изменились. Перечитай список и повтори действие.");
      }
      const group = this.world.groups.find((item) => item.id === id);
      if (!group) throw new Error(`Группа «${id}» не найдена.`);
      const matched = this.processes(group);
      const serviceNames = this.services(group);
      if (!stop) {
        return {
          matched,
          caller_in_group: false,
          services: serviceNames.map((name) => ({ name, status: "Running", error: null })),
        } satisfies Outcome;
      }
      const remaining = matched.filter((process) => !process.owned);
      const services = serviceNames.map((name, index) =>
        index === 0
          ? { name, status: "Running", error: "Отказано в доступе." }
          : { name, status: "Stopped", error: null },
      );
      return {
        matched,
        stopped: matched.filter((process) => process.owned),
        remaining,
        complete: remaining.length === 0 && services.every((service) => service.status === "Stopped"),
        services,
      } satisfies Outcome;
    },
    change_protection: async (args) => {
      await this.runProtection((args as { action: ProtectionAction }).action);
      return null;
    },
    guard_status: async () => {
      // The real read takes about 2 s (netsh + firewall policy), diagnose about 3 s.
      await this.wait(2000);
      const status = this.status();
      this.emit("guard-state", status);
      this.schedulePoll();
      return status;
    },
    diagnose: async () => {
      await this.wait(3000);
      return this.diagnosis();
    },
    core_rules_state: async () => {
      await this.wait(400);
      return this.coreRules();
    },
    reload_core: async () => {
      await this.wait(1800);
      const w = this.world;
      if (!w.coreRunning) throw new Error("Mihomo не запущен. Запусти профиль в v2rayN.");
      w.coreRules = [...w.rules];
      this.emit("guard-state", this.status());
      return this.coreRules();
    },
    detect_client: async () => {
      await this.wait(1500);
      const w = this.world;
      const found: ClientDetection =
        this.scenario === "unconfigured"
          ? {
              settings: { client_path: v2raynPath, adapter: "Mihomo", proxy_port: 10808 },
              candidates: ["D:\\Portable\\v2rayN-7.9\\v2rayN.exe"],
              note: "Найдены две копии v2rayN. Выбрана та, что запущена сейчас.",
            }
          : {
              settings: { ...w.settings, client_path: w.settings.client_path || v2raynPath },
              candidates: [],
              note: w.clientRunning ? null : "v2rayN сейчас не запущен — порт взят из guiNConfig.json.",
            };
      return found;
    },
    set_window_visible: (args) => {
      this.visible = Boolean((args as { visible: boolean }).visible);
      this.schedulePoll();
      return Promise.resolve(null);
    },
  };
}

let instance: MockBackend | undefined;

export function getMockBackend(): MockBackend {
  instance ??= new MockBackend(readScenario());
  return instance;
}

export function createMockTransport(): Transport {
  const backend = getMockBackend();
  console.info(`[mock] сценарий «${backend.scenario}»: ${scenarios[backend.scenario]}`);
  return { invoke: backend.invoke, listen: backend.listen };
}
