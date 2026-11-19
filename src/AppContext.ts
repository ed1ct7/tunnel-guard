import { createContext, useContext } from "react";
import type { ProtectionAction, Status } from "./api/types";
import type { Page } from "./domain/navigation";
import type { StatusView } from "./domain/status";
import type { ConfigStore } from "./hooks/useConfigState";
import type { useCoreRules, useDiagnosis } from "./hooks/useDiagnosis";
import type { ProtectionController } from "./hooks/useProtection";

/** State and actions shared by the pages. Built once in <App>. */
export type AppModel = {
  page: Page;
  navigate: (page: Page) => void;
  status: Status | null;
  statusError: string | null;
  refreshingStatus: boolean;
  view: StatusView;
  diagnosis: ReturnType<typeof useDiagnosis>;
  coreRules: ReturnType<typeof useCoreRules>;
  config: ConfigStore;
  protection: ProtectionController;
  /** Status + readiness, as the "Обновить" button does. */
  refreshAll: () => Promise<void>;
  requestProtection: (action: ProtectionAction) => Promise<void>;
  openClient: () => Promise<void>;
  openingClient: boolean;
  /** Re-reads settings and rules from disk, asking first if drafts would be lost. */
  reloadConfig: () => Promise<void>;
};

export const AppContext = createContext<AppModel | null>(null);

export function useApp() {
  const model = useContext(AppContext);
  if (!model) throw new Error("useApp outside <App>");
  return model;
}
