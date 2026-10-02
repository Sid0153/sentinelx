import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  failed: boolean;
}

/**
 * A page that throws while rendering (an unexpected response shape, a bug) shows this message
 * instead of blanking the whole app; the navigation stays usable. The layout keys it by path,
 * so moving to another page starts fresh.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // The browser console only: nothing is sent anywhere, and error text can carry data.
    console.error("page.render_failed", error, info.componentStack);
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div role="alert" className="rounded-lg border border-rose-900 bg-rose-950/40 p-4 text-sm text-rose-200">
        <p className="font-medium">This page could not be shown.</p>
        <p className="mt-1 text-rose-300">
          Something unexpected happened while drawing it. Other pages still work; reloading may
          help. If it keeps happening, the browser console has the details for a bug report.
        </p>
        <button
          type="button"
          className="mt-3 rounded border border-rose-800 px-3 py-1 text-rose-100 hover:bg-rose-900/40"
          onClick={() => window.location.reload()}
        >
          Reload
        </button>
      </div>
    );
  }
}
