import * as React from "react";

import { cn } from "@/lib/utils";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "flex h-9 w-full rounded-md border border-line-strong bg-surface px-3 text-[13px] text-ink placeholder:text-faint",
        "focus-visible:border-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/15",
        "disabled:cursor-not-allowed disabled:bg-sunken aria-[invalid=true]:border-bad",
        "file:mr-3 file:border-0 file:bg-transparent file:text-[13px] file:font-medium",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";
