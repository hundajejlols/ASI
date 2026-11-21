import { ChevronDown } from 'lucide-react';
import React from 'react';
import { cn } from '../../lib/utils';

export const Select = React.forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement>
>(({ className, children, ...props }, ref) => (
  <div className="relative inline-flex items-center w-full">
    <select
      ref={ref}
      className={cn(
        'flex h-9 w-full appearance-none rounded-md border border-input bg-background pl-3 pr-8 py-1.5 text-xs text-foreground',
        'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
        'disabled:cursor-not-allowed disabled:opacity-45',
        className
      )}
      {...props}
    >
      {children}
    </select>
    <ChevronDown className="pointer-events-none absolute right-2.5 h-3.5 w-3.5 text-muted-foreground" />
  </div>
));
Select.displayName = 'Select';
