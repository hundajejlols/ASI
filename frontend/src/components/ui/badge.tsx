import React from 'react';
import { cn } from '../../lib/utils';

export type BadgeVariant = 'default' | 'secondary' | 'outline';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
}

const BADGE_VARIANTS: Record<BadgeVariant, string> = {
  default: 'bg-primary text-primary-foreground border-transparent',
  secondary: 'bg-secondary text-secondary-foreground border-border',
  outline: 'bg-transparent text-foreground border-border',
};

export function Badge({ className, variant = 'outline', ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium leading-tight',
        BADGE_VARIANTS[variant],
        className
      )}
      {...props}
    />
  );
}
