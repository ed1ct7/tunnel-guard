import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorText, onEvent } from "../api/backend";
import type { Status } from "../api/types";

function normalise(status: Status): Status {
  // An older backend does not send `checked_at`; treat the moment of arrival as the read time.
  return { ...status, checked_at: status.checked_at || Date.now() };
}

/** Live protection status: initial read, `guard-state` events and an explicit refresh. */
export function useGuardStatus() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const reading = useRef(false);

  const read = useCallback(() => {
    if (reading.current) return Promise.resolve();
    reading.current = true;
    return api
      .guardStatus()
      .then(
        (value) => {
          setStatus(normalise(value));
          setError(null);
        },
        (reason: unknown) => {
          setStatus({ state: "Unknown", adapter_up: false, checked_at: Date.now() });
          setError(errorText(reason));
        },
      )
      .finally(() => {
        reading.current = false;
        setRefreshing(false);
      });
  }, []);

  const refresh = useCallback(() => {
    setRefreshing(true);
    return read();
  }, [read]);

  useEffect(() => {
    const stop = onEvent("guard-state", (payload) => {
      setStatus(normalise(payload));
      setError(null);
    });
    void read();
    return stop;
  }, [read]);

  return { status, error, refreshing, refresh };
}
