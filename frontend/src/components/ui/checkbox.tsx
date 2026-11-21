import * as CheckboxPrimitive from '@radix-ui/react-checkbox';
import * as SwitchPrimitive from '@radix-ui/react-switch';
import { Check } from 'lucide-react';
import React from 'react';
import { cn } from '../../lib/utils';

export function Checkbox({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      className={cn(
        'peer h-4 w-4 shrink-0 rounded-sm border border-foreground/70 bg-background',
        'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
        'disabled:cursor-not-allowed disabled:opacity-45',
        'data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground data-[state=checked]:border-primary',
        className
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator className="flex items-center justify-center text-current">
        <Check className="h-3 w-3 stroke-[2.5]" />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

export function Switch({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      className={cn(
        'peer inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border border-border transition-colors',
        'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
        'disabled:cursor-not-allowed disabled:opacity-45',
        'data-[state=checked]:bg-primary data-[state=unchecked]:bg-secondary',
        className
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        className={cn(
          'pointer-events-none block h-3.5 w-3.5 rounded-full transition-transform',
          'data-[state=checked]:translate-x-4 data-[state=checked]:bg-primary-foreground',
          'data-[state=unchecked]:translate-x-0.5 data-[state=unchecked]:bg-foreground'
        )}
      />
    </SwitchPrimitive.Root>
  );
}
