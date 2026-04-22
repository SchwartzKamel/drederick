import { Toaster as SonnerToaster } from "sonner";
import type { ToasterProps } from "sonner";

/**
 * Toaster component. Pages that want to raise toasts should import
 * `toast` from `@/lib/toast` (split out so this file only exports
 * components — react-refresh requirement).
 */
export function Toaster(props?: ToasterProps) {
  return (
    <SonnerToaster
      richColors
      position="bottom-right"
      theme="dark"
      closeButton
      {...props}
    />
  );
}
