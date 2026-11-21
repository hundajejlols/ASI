import React from 'react';
import { cn } from '../../lib/utils';

export type ButtonVariant = 'default' | 'secondary' | 'outline' | 'ghost' | 'destructive';
export type ButtonSize = 'default' | 'sm' | 'lg' | 'icon';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  default: 'bg-primary text-primary-foreground hover:bg-primary/90 border border-transparent',
  secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80 border border-border',
  outline: 'bg-transparent text-foreground border border-border hover:bg-secondary/60',
  ghost: 'bg-transparent text-muted-foreground hover:bg-secondary/50 hover:text-foreground',
  destructive: 'bg-foreground text-background hover:bg-foreground/85 border border-foreground',
};

const SIZE_CLASSES: Record<ButtonSize, string> = {
  default: 'h-9 px-3.5 py-2 text-xs',
  sm: 'h-8 px-2.5 py-1.5 text-xs',
  lg: 'h-10 px-5 text-sm',
  icon: 'h-8 w-8 p-0',
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'default', type = 'button', ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn(
        'inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors',
        'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
        'disabled:pointer-events-none disabled:opacity-45',
        VARIANT_CLASSES[variant],
        SIZE_CLASSES[size],
        className
      )}
      {...props}
    />
  )
);
Button.displayName = 'Button';
