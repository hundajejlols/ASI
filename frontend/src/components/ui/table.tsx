import React from 'react';
import { cn } from '../../lib/utils';

export function Table({ className, ...props }: React.TableHTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn('w-full text-left text-xs border-collapse', className)} {...props} />
    </div>
  );
}

export function TableHeader({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <thead className={cn('border-b border-border bg-muted/60 text-muted-foreground', className)} {...props} />;
}

export function TableBody({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody className={cn('divide-y divide-border/80', className)} {...props} />;
}

export function TableRow({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr
      className={cn('transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted', className)}
      {...props}
    />
  );
}

export function TableHead({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      className={cn('h-9 px-4 text-left align-middle font-medium text-muted-foreground whitespace-nowrap', className)}
      {...props}
    />
  );
}

export function TableCell({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn('px-4 py-3 align-middle text-foreground', className)} {...props} />;
}
