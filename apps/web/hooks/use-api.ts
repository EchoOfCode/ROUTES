"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api, ApiError } from "@/lib/api";

/** Minimal data hook: fetch on mount, optional polling while `poll` returns true. */
export function useApi<T>(path: string | null, options: { poll?: (data: T) => boolean; intervalMs?: number } = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState<boolean>(path !== null);
  const pollRef = useRef(options.poll);
  pollRef.current = options.poll;

  const load = useCallback(async () => {
    if (path === null) return;
    try {
      const result = await api<T>(path);
      setData(result);
      setError(null);
      return result;
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "network", "Could not reach ROUTES."));
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      const result = await load();
      if (cancelled) return;
      if (result !== undefined && pollRef.current?.(result)) {
        timer = setTimeout(tick, options.intervalMs ?? 2000);
      }
    };
    setLoading(path !== null);
    tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [load, path, options.intervalMs]);

  return { data, error, loading, reload: load, setData };
}
