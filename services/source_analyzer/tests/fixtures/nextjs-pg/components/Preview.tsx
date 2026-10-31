"use client";

import { useEffect, useRef } from "react";

export function Preview() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) {
      ref.current.innerHTML = location.search;
    }
  }, []);
  return <div ref={ref} />;
}
