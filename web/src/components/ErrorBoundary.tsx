import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("[drederick] unhandled render error", error);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground">
          <div className="max-w-lg rounded-xl border border-destructive/50 bg-card p-6 shadow">
            <h1 className="mb-2 font-mono text-lg font-bold text-destructive">
              Something broke.
            </h1>
            <p className="mb-4 text-sm text-muted-foreground">
              The operator pane hit a render error. Reload to retry.
            </p>
            <pre className="mb-4 max-h-48 overflow-auto rounded bg-muted p-3 font-mono text-xs">
              {this.state.error.message}
            </pre>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
