import { createRoot } from "react-dom/client";
import { App } from "./App.js";
import { ErrorBoundary } from "./components/ErrorBoundary.js";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root element");

// NOTE: intentionally NOT wrapped in <StrictMode>. React 18 StrictMode
// double-invokes mount effects in dev (mount → unmount → remount), which builds
// and tears down the imperative Cytoscape canvas twice on load — wasteful, and a
// common source of subtle teardown bugs with canvas libraries. Dropping the
// double-invoke keeps the canvas lifecycle simple. (Production never
// double-invokes, so behaviour is unchanged.)
createRoot(root).render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>,
);
