import React from 'react';
import { cn } from '../../lib/utils';

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'destructive';
}

export function Alert({ className, variant = 'default', ...props }: AlertProps) {
  return (
    <div
      role="alert"
      className={cn(
        'relative w-full rounded-md border px-3.5 py-2.5 text-xs flex items-start gap-2.5',
        variant === 'destructive'
          ? 'border-foreground bg-secondary/80 text-foreground'
          : 'border-border bg-muted/60 text-foreground',
        className
      )}
      {...props}
    />
  );
}

export function AlertTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h5 className={cn('font-semibold leading-none tracking-tight', className)} {...props} />;
}

export function AlertDescription({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('text-xs text-muted-foreground leading-relaxed', className)} {...props} />;
}
