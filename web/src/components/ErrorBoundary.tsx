import { Component, type ReactNode } from "react";
import { tatumisms } from "@/lib/tatumisms";

interface Props {
  children: ReactNode;
  fallback?: (error: Error, reset: () => void) => ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Class-component error boundary that surfaces the Tatum-voiced
 * "Dear God, why are we fighting?" message when a descendant throws
 * during render. `reset` clears the error so the subtree can re-mount
 * without a full page reload.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("[drederick] unhandled render error", error);
  }

  private reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.fallback) return this.props.fallback(error, this.reset);

    const copy = tatumisms.errors.boundary;
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground">
        <div
          role="alert"
          className="max-w-lg rounded-xl border border-destructive/50 bg-card p-6 shadow"
        >
          <h1 className="mb-2 font-mono text-lg font-bold text-destructive">
            {copy.title}
          </h1>
          <p className="mb-4 text-sm text-muted-foreground">{copy.body}</p>
          <pre className="mb-4 max-h-48 overflow-auto rounded bg-muted p-3 font-mono text-xs">
            {error.message}
          </pre>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={this.reset}
              className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              {tatumisms.actions.retry}
            </button>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground hover:bg-accent"
            >
              {tatumisms.actions.reload}
            </button>
          </div>
        </div>
      </div>
    );
  }
}
