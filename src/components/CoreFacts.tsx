import type { CoreRulesState, Diagnosis, ProxyGroup, Settings } from "../api/types";

const modeNames: Record<string, string> = { rule: "Rule", global: "Global", direct: "Direct" };

type Route = { server: string; path: string[] };

/**
 * Collapse selector chains (PROXY → auto → NL-01) into the server actually in use,
 * keeping the group path as a hint. Only top-level groups (not chosen by another group) start a chain.
 */
function resolveRoutes(groups: ProxyGroup[]): Route[] {
  const byName = new Map(groups.map((group) => [group.name, group]));
  const chosen = new Set(groups.map((group) => group.now).filter((now): now is string => !!now));
  const routes: Route[] = [];
  const seen = new Set<string>();
  for (const root of groups) {
    if (!root.now || chosen.has(root.name)) continue;
    const path: string[] = [];
    let current: ProxyGroup | undefined = root;
    let server = root.now;
    while (current?.now && !path.includes(current.name)) {
      path.push(current.name);
      server = current.now;
      current = byName.get(current.now);
    }
    if (seen.has(server)) continue;
    seen.add(server);
    routes.push({ server, path });
  }
  return routes;
}

/** Facts about the running core and the saved connection, for people who want the details. */
export function CoreFacts({
  diagnosis,
  settings,
  coreRules,
}: {
  diagnosis: Diagnosis | null;
  settings: Settings;
  coreRules: CoreRulesState | null;
}) {
  const core = diagnosis?.core ?? null;
  const routes = resolveRoutes(core?.groups ?? []);
  return (
    <section className="panel facts" aria-labelledby="facts-title">
      <header className="panel-head">
        <h2 id="facts-title">Ядро и подключение</h2>
      </header>
      {diagnosis && !core && (
        <p className="panel-note">
          Контроллер Mihomo не отвечает — данные ядра появятся, когда профиль в v2rayN запущен.
        </p>
      )}
      <dl className="facts-list">
        {core && (
          <>
            <div>
              <dt>Mihomo</dt>
              <dd>{core.version ?? "версия неизвестна"}</dd>
            </div>
            <div>
              <dt>Режим</dt>
              <dd>{core.mode ? (modeNames[core.mode] ?? core.mode) : "—"}</dd>
            </div>
            <div>
              <dt>TUN</dt>
              <dd>{core.tun_enabled ? (core.tun_device ?? "включён") : "выключен"}</dd>
            </div>
            {routes.length > 0 && (
              <div>
                <dt>{routes.length > 1 ? "Серверы" : "Сервер"}</dt>
                <dd>
                  <ul className="facts-groups">
                    {routes.slice(0, 3).map((route) => (
                      <li key={route.server}>
                        <span>{route.server}</span>
                        <span className="facts-group-path">{route.path.join(" → ")}</span>
                      </li>
                    ))}
                  </ul>
                </dd>
              </div>
            )}
          </>
        )}
        <div>
          <dt>Адаптер</dt>
          <dd>{settings.adapter || "—"}</dd>
        </div>
        <div>
          <dt>Порт прокси</dt>
          <dd className="num">{settings.proxy_port}</dd>
        </div>
        {coreRules && (
          <div>
            <dt>Правила</dt>
            <dd>
              {coreRules.state === "applied"
                ? "применены в ядре"
                : coreRules.state === "pending"
                  ? "сохранены, ждут применения"
                  : "не сравнить с ядром"}
            </dd>
          </div>
        )}
      </dl>
    </section>
  );
}
