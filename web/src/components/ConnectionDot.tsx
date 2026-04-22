import { useSignalREvents } from "@/api/signalr";
import { cn } from "@/lib/utils";

export function ConnectionDot() {
  const { state } = useSignalREvents("recon");
  const dot = {
    connected: "bg-emerald-500",
    connecting: "bg-amber-500",
    disconnected: "bg-muted-foreground",
    error: "bg-destructive",
  }[state];

  return (
    <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
      <span className={cn("inline-block h-2 w-2 rounded-full", dot)} aria-hidden />
      <span>hub: {state}</span>
    </div>
  );
}
