import { Link } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  Flag,
  Flame,
  HeartPulse,
  Notebook,
  ScrollText,
  Target,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const TILES = [
  { to: "/runs", title: "Runs", description: "Active + historical harness runs.", icon: Activity },
  { to: "/findings", title: "Findings", description: "Service + CVE enrichment.", icon: AlertTriangle },
  { to: "/jeopardy", title: "Jeopardy", description: "CTF-style target board.", icon: Flag },
  { to: "/offensive", title: "Offensive", description: "Exploit, cred, payload actions.", icon: Flame },
  { to: "/audit", title: "Audit", description: "Append-only audit stream.", icon: ScrollText },
  { to: "/scope", title: "Scope", description: "Authorization allow-list.", icon: Target },
  { to: "/doctor", title: "Doctor", description: "Operator workstation preflight.", icon: HeartPulse },
  { to: "/notes", title: "Notes", description: "Operator scratchpad.", icon: Notebook },
] as const;

export function DashboardPage() {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {TILES.map(({ to, title, description, icon: Icon }) => (
        <Link key={to} to={to} className="group">
          <Card className="h-full transition-colors group-hover:border-primary/50">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
                <CardTitle className="font-mono text-sm">{title}</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <CardDescription>{description}</CardDescription>
              <p className="mt-2 text-xs text-muted-foreground">
                <span className="font-mono">phase 3</span> — placeholder
              </p>
            </CardContent>
          </Card>
        </Link>
      ))}
    </div>
  );
}
