import { useEffect, useReducer } from "react";
import { onEvent } from "../api/backend";
import type { ConfigSnapshot, Settings } from "../api/types";
import { countChanges, equalLists } from "../domain/rules";
import { defaultSettings, sameSettings } from "../domain/settings";

export type ConfigState = {
  loaded: boolean;
  /** Settings as saved on disk. */
  configured: Settings;
  /** Settings being edited on the Connection page. */
  settings: Settings;
  /** Rules as saved in Mixin.yaml. */
  savedRules: string[];
  /** Rules being edited on the Routing page. */
  rules: string[];
  /** Another program changed the config while the window had unsaved drafts. */
  conflict: boolean;
};

type ConfigAction =
  | { type: "sync"; snapshot: ConfigSnapshot }
  | { type: "replace"; snapshot: ConfigSnapshot }
  | { type: "editSettings"; settings: Settings }
  | { type: "editRules"; rules: string[] }
  | { type: "rulesLoaded"; rules: string[] }
  | { type: "settingsSaved"; settings: Settings }
  | { type: "revertRules" }
  | { type: "dismissConflict" };

const initialState: ConfigState = {
  loaded: false,
  configured: defaultSettings,
  settings: defaultSettings,
  savedRules: [],
  rules: [],
  conflict: false,
};

/**
 * Applies a config snapshot from disk. Same decision table as 0.4 `syncConfig`: a change from another
 * program is taken over silently unless it would overwrite a draft that differs from it.
 */
function sync(state: ConfigState, snapshot: ConfigSnapshot): ConfigState {
  const incomingRules = snapshot.rules ?? [];
  const settingsChanged = !sameSettings(state.configured, snapshot.settings);
  const rulesChanged = !equalLists(state.savedRules, incomingRules);
  if (!settingsChanged && !rulesChanged) return state.loaded ? state : { ...state, loaded: true };
  const rulesDirty = !equalLists(state.rules, state.savedRules);
  const settingsDraftLost =
    settingsChanged &&
    !sameSettings(state.settings, state.configured) &&
    !sameSettings(state.settings, snapshot.settings);
  const rulesDraftLost =
    rulesDirty && (settingsChanged || rulesChanged) && !equalLists(state.rules, incomingRules);
  if (settingsDraftLost || rulesDraftLost) return { ...state, loaded: true, conflict: true };
  return {
    ...state,
    loaded: true,
    configured: settingsChanged ? snapshot.settings : state.configured,
    settings: settingsChanged ? snapshot.settings : state.settings,
    savedRules: incomingRules,
    rules: incomingRules,
  };
}

function reducer(state: ConfigState, action: ConfigAction): ConfigState {
  switch (action.type) {
    case "sync":
      return sync(state, action.snapshot);
    case "replace":
      return {
        loaded: true,
        configured: action.snapshot.settings,
        settings: action.snapshot.settings,
        savedRules: action.snapshot.rules ?? [],
        rules: action.snapshot.rules ?? [],
        conflict: false,
      };
    case "editSettings":
      return { ...state, settings: action.settings };
    case "editRules":
      return { ...state, rules: action.rules };
    case "rulesLoaded":
      return { ...state, savedRules: action.rules, rules: action.rules };
    case "settingsSaved":
      // A different v2rayN means a different Mixin.yaml: the old list is no longer meaningful.
      return { ...state, configured: action.settings, settings: action.settings, savedRules: [], rules: [] };
    case "revertRules":
      return { ...state, rules: state.savedRules };
    case "dismissConflict":
      return { ...state, conflict: false };
  }
}

/** Saved config plus the unsaved drafts of the Connection and Routing pages. */
export function useConfigState() {
  const [state, dispatch] = useReducer(reducer, initialState);

  useEffect(() => onEvent("guard-config", (snapshot) => dispatch({ type: "sync", snapshot })), []);

  const rulesDirty = !equalLists(state.rules, state.savedRules);
  return {
    ...state,
    rulesDirty,
    ruleChanges: rulesDirty ? countChanges(state.savedRules, state.rules) : 0,
    settingsDirty: !sameSettings(state.settings, state.configured),
    dispatch,
  };
}

export type ConfigStore = ReturnType<typeof useConfigState>;
