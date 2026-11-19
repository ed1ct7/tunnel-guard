import { useApp } from "../AppContext";
import { Checklist } from "../components/Checklist";
import { CoreFacts } from "../components/CoreFacts";
import { StatusHero } from "../components/StatusHero";
import type { CheckFixLink } from "../domain/checks";
import { primaryAction } from "../domain/status";

export function OverviewPage() {
  const app = useApp();
  const { status, diagnosis, protection, config } = app;
  const primary = primaryAction(status);

  function fix(link: CheckFixLink) {
    if (link === "connection") app.navigate("connection");
    else void app.openClient();
  }

  return (
    <div className="page page-overview">
      <StatusHero
        status={status}
        statusError={app.statusError}
        view={app.view}
        adapter={config.configured.adapter}
        refreshing={app.refreshingStatus || diagnosis.loading}
        onRefresh={() => void app.refreshAll()}
        primary={primary}
        onPrimary={() => void app.requestProtection(primary.action)}
        clientConfigured={!config.loaded || Boolean(config.configured.client_path)}
        onOpenClient={() => void app.openClient()}
        openingClient={app.openingClient}
        diagnosis={diagnosis.diagnosis}
        run={protection.run}
        progressVisible={protection.dialogOpen}
        onShowProgress={protection.showDialog}
      />
      <div className="overview-grid">
        <Checklist
          title="Готовность к защите"
          diagnosis={diagnosis.diagnosis}
          error={diagnosis.error}
          loading={diagnosis.loading}
          onRefresh={() => void diagnosis.refresh()}
          onFix={fix}
        />
        <CoreFacts
          diagnosis={diagnosis.diagnosis}
          settings={config.configured}
          coreRules={app.coreRules.coreRules}
        />
      </div>
    </div>
  );
}
