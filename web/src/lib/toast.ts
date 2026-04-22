import { toast as sonnerToast } from "sonner";
import type { ExternalToast } from "sonner";
import { tatumisms, type TatumErrorKind } from "./tatumisms";

/**
 * Toast helpers. Thin wrapper over sonner so pages can get
 * Tatum-voiced defaults on error / scope-rejection without repeating
 * the microcopy lookup.
 *
 * Usage:
 *   toast.success("Run enqueued.");
 *   toast.error("Scope rejected.", { description: "That target is wild." });
 *   toast.fromTatum("scope_rejected");
 */
export const toast = Object.assign(
  (message: string, opts?: ExternalToast) => sonnerToast(message, opts),
  {
    success: sonnerToast.success,
    error: sonnerToast.error,
    info: sonnerToast.info,
    warning: sonnerToast.warning,
    loading: sonnerToast.loading,
    dismiss: sonnerToast.dismiss,
    promise: sonnerToast.promise,
    message: sonnerToast.message,
    /**
     * Raise a Tatum-voiced error toast. Title is the microcopy; body
     * becomes the description. Caller can override via `opts`.
     */
    fromTatum(kind: TatumErrorKind, opts?: ExternalToast) {
      const copy = tatumisms.errors[kind];
      return sonnerToast.error(copy.title, { description: copy.body, ...opts });
    },
  },
);
