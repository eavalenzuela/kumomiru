import { Component, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * Catches render/lifecycle throws below it so a single failure — most likely
 * from the imperative Cytoscape canvas or a malformed graph — degrades to a
 * readable, recoverable panel instead of React unmounting the whole tree to a
 * blank white page. "Try again" clears the boundary and re-mounts the subtree.
 */
export class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  override state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    // Surface the failure in the console for debugging; never swallow silently.
    console.error("kumomiru viewer crashed:", error, info.componentStack);
  }

  private reset = (): void => this.setState({ error: null });

  override render(): ReactNode {
    if (this.state.error) {
      return (
        <div className="app-state">
          <h1>kumomiru</h1>
          <p className="error">Something went wrong rendering the map.</p>
          <p className="hint">{this.state.error.message}</p>
          <button type="button" className="ds-primary" onClick={this.reset}>
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
