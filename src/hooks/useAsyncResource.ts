import { useCallback, useRef, useState } from "react";
import { errorText } from "../api/backend";

/**
 * A read-only backend value that is re-fetched on demand. Concurrent `load` calls share one request.
 * `loading` is true until the first answer and during explicit refreshes.
 */
export function useAsyncResource<T>(fetcher: () => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const pending = useRef<Promise<T | null> | null>(null);

  const load = useCallback(() => {
    if (pending.current) return pending.current;
    const request = fetcher()
      .then(
        (value) => {
          setData(value);
          setError(null);
          return value;
        },
        (reason: unknown) => {
          setError(errorText(reason));
          return null;
        },
      )
      .finally(() => {
        pending.current = null;
        setLoading(false);
      });
    pending.current = request;
    return request;
  }, [fetcher]);

  /** Same as `load`, but shows the loading state (for buttons the user pressed). */
  const refresh = useCallback(() => {
    setLoading(true);
    return load();
  }, [load]);

  return { data, error, loading, load, refresh, setData };
}
