import { useCallback } from "react";
import { api } from "../api/backend";
import { useAsyncResource } from "./useAsyncResource";

/** Readiness checklist from `diagnose()` (read-only, ~1–2 s). */
export function useDiagnosis() {
  const resource = useAsyncResource(api.diagnose);
  return {
    diagnosis: resource.data,
    error: resource.error,
    loading: resource.loading,
    load: resource.load,
    refresh: resource.refresh,
  };
}

/** Whether the running Mihomo uses the saved prepend-rules. */
export function useCoreRules() {
  const resource = useAsyncResource(api.coreRulesState);
  const { setData } = resource;
  const reload = useCallback(async () => {
    const state = await api.reloadCore();
    setData(state);
    return state;
  }, [setData]);
  return {
    coreRules: resource.data,
    error: resource.error,
    loading: resource.loading,
    load: resource.load,
    refresh: resource.refresh,
    reload,
  };
}
