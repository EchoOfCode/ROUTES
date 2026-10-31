import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md text-[13px] font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary: "bg-ink text-white hover:bg-ink-2",
        accent: "bg-accent text-white hover:bg-accent-hover",
        secondary: "border border-line-strong bg-surface text-ink hover:bg-sunken",
        ghost: "text-ink-2 hover:bg-sunken hover:text-ink",
        danger: "border border-line-strong bg-surface text-bad hover:border-[#f0c6c2] hover:bg-[#fdf3f2]",
        link: "h-auto px-0 text-accent underline-offset-4 hover:underline",
      },
      size: { sm: "h-7 px-2.5", md: "h-8 px-3", lg: "h-10 px-4 text-sm", icon: "size-8" },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return <Comp ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />;
  },
);
Button.displayName = "Button";
