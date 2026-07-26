'use client';

import { useEffect } from 'react';

/** Client-side redirect for static export (next/navigation redirect is unreliable with output:export). */
export function DocsRedirect({ href }: { href: string }) {
  useEffect(() => {
    window.location.replace(href);
  }, [href]);

  return (
    <div className="flex min-h-[40vh] flex-col items-center justify-center gap-3 p-8 text-center">
      <p className="text-sm text-fd-muted-foreground">Redirecting…</p>
      <a href={href} className="text-sm font-medium text-fd-primary underline underline-offset-2">
        Continue to documentation
      </a>
    </div>
  );
}
