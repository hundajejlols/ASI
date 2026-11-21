import * as DialogPrimitive from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import React from 'react';
import { cn } from '../../lib/utils';

export const Sheet = DialogPrimitive.Root;
export const SheetTrigger = DialogPrimitive.Trigger;
export const SheetClose = DialogPrimitive.Close;

export function SheetContent({
  className,
  children,
  ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content>) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/75 backdrop-blur-[1px]" />
      <DialogPrimitive.Content
        className={cn(
          'fixed inset-y-0 right-0 z-50 h-full w-full max-w-2xl border-l border-border bg-background p-6 text-foreground focus:outline-none flex flex-col',
          className
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close
          aria-label="Zamknij"
          className="absolute right-5 top-5 rounded-md border border-border bg-secondary/60 p-1.5 text-muted-foreground hover:text-foreground transition-colors"
        >
          <X className="h-3.5 w-3.5" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export function SheetHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex flex-col gap-1 pr-8', className)} {...props} />;
}

export function SheetTitle({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>) {
  return <DialogPrimitive.Title className={cn('text-base font-semibold text-foreground', className)} {...props} />;
}

export function SheetDescription({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>) {
  return <DialogPrimitive.Description className={cn('text-xs text-muted-foreground', className)} {...props} />;
}
