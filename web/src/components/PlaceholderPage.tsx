import type { ReactNode } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export interface PlaceholderPageProps {
  title: string;
  tagline: string;
  children?: ReactNode;
}

export function PlaceholderPage({ title, tagline, children }: PlaceholderPageProps) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="font-mono text-xl">{title}</CardTitle>
          <Badge variant="secondary">coming in phase 3</Badge>
        </div>
        <CardDescription>{tagline}</CardDescription>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        {children ?? (
          <p>This view is a scaffold placeholder. Phase 3 agents fill it in.</p>
        )}
      </CardContent>
    </Card>
  );
}
