import { useState } from "react";
import { Megaphone, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { tatumisms } from "@/lib/tatumisms";
import { SessionStartForm } from "./SessionStartForm";
import { SessionsTable } from "./SessionsTable";

/**
 * Jeopardy landing. Billing line, opening-bell CTA, sessions table.
 */
export function JeopardyPage() {
  const [showForm, setShowForm] = useState(false);

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-3">
            <div>
              <CardTitle className="font-mono text-2xl">
                The Jeopardy Division
              </CardTitle>
              <CardDescription className="mt-1 italic">
                {tatumisms.banner.billing} I would be delighted to inform you
                that the CTFd arena is open for business.
              </CardDescription>
            </div>
            <Button onClick={() => setShowForm((v) => !v)} size="lg">
              {showForm ? (
                <>
                  <Megaphone className="h-4 w-4" aria-hidden />
                  Hide weigh-in
                </>
              ) : (
                <>
                  <Plus className="h-4 w-4" aria-hidden />
                  Ring the opening bell
                </>
              )}
            </Button>
          </div>
        </CardHeader>
        {showForm ? (
          <CardContent>
            <SessionStartForm
              onStarted={() => setShowForm(false)}
              onCancel={() => setShowForm(false)}
            />
          </CardContent>
        ) : null}
      </Card>

      <section className="flex flex-col gap-3">
        <h2 className="font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Active &amp; past bouts
        </h2>
        <SessionsTable />
      </section>
    </div>
  );
}
