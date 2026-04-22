import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/api/client";
import { cn } from "@/lib/utils";

export function HealthIndicator() {
  const { data, isError, isLoading } = useQuery({
    queryKey: ["health"],
    queryFn: async () => {
      const { data, error } = await apiClient.GET("/api/health");
      if (error) throw new Error("health failed");
      return data;
    },
    refetchInterval: 10_000,
    retry: 0,
  });

  const status: "ok" | "down" | "pending" = isLoading
    ? "pending"
    : isError || !data
      ? "down"
      : "ok";

  const dot = {
    ok: "bg-emerald-500",
    down: "bg-destructive",
    pending: "bg-muted-foreground",
  }[status];

  const label = {
    ok: "healthy",
    down: "unreachable",
    pending: "checking",
  }[status];

  return (
    <div className="flex items-center gap-2 font-mono">
      <span className={cn("inline-block h-2 w-2 rounded-full", dot)} aria-hidden />
      <span>/api/health: {label}</span>
    </div>
  );
}
