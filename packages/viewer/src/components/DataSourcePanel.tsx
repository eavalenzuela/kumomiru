import { useEffect, useRef, useState } from "react";
import type { Graph } from "@kumomiru/graph";
import {
  fetchSample,
  postTerraform,
  postLive,
  leastPrivilegePolicyUrl,
  type LiveCredentials,
} from "../lib/api.js";

type Tab = "sample" | "terraform" | "live";

interface DataSourcePanelProps {
  onLoad: (graph: Graph) => void;
  onClose: () => void;
}

/**
 * Modal for choosing the map's data source. The viewer previously only ever
 * loaded /sample; this exposes the two ingestion paths the server already has —
 * Terraform state (no credentials) and live read-only AWS discovery.
 *
 * Credential discipline (DESIGN.md §6A): live credentials are held only in local
 * component state, sent once in the POST body over TLS, and cleared the moment
 * the request resolves — never written to localStorage, the URL, or logs.
 */
export function DataSourcePanel({ onLoad, onClose }: DataSourcePanelProps) {
  const [tab, setTab] = useState<Tab>("terraform");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Move focus into the dialog on open and let Escape dismiss it (a11y).
  const modalRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    modalRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Terraform inputs.
  const [tfText, setTfText] = useState("");

  // Live inputs.
  const [creds, setCreds] = useState<LiveCredentials>({
    accessKeyId: "",
    secretAccessKey: "",
    sessionToken: "",
    region: "us-east-1",
  });

  const run = async (fn: () => Promise<Graph>, after?: () => void) => {
    setBusy(true);
    setError(null);
    try {
      const graph = await fn();
      after?.();
      onLoad(graph);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const loadSample = () => run(fetchSample);

  const loadTerraformText = (text: string) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      setError("That doesn't look like valid JSON.");
      return;
    }
    run(() => postTerraform(parsed));
  };

  const onFile = (file: File | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => loadTerraformText(String(reader.result));
    reader.onerror = () => setError("Could not read the file.");
    reader.readAsText(file);
  };

  const loadLive = () => {
    const body: LiveCredentials = {
      accessKeyId: creds.accessKeyId.trim(),
      secretAccessKey: creds.secretAccessKey.trim(),
      region: creds.region.trim(),
      ...(creds.sessionToken?.trim()
        ? { sessionToken: creds.sessionToken.trim() }
        : {}),
    };
    // Clear the credential fields immediately — they live only for this request.
    run(
      () => postLive(body),
      () =>
        setCreds({
          accessKeyId: "",
          secretAccessKey: "",
          sessionToken: "",
          region: creds.region,
        }),
    );
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label="Load data"
        ref={modalRef}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <h2>Load data</h2>
          <button
            type="button"
            className="inspector-close"
            onClick={onClose}
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        <div className="ds-tabs" role="tablist">
          <button
            role="tab"
            aria-selected={tab === "terraform"}
            className={tab === "terraform" ? "active" : ""}
            onClick={() => setTab("terraform")}
          >
            Terraform state
          </button>
          <button
            role="tab"
            aria-selected={tab === "live"}
            className={tab === "live" ? "active" : ""}
            onClick={() => setTab("live")}
          >
            Live AWS
          </button>
          <button
            role="tab"
            aria-selected={tab === "sample"}
            className={tab === "sample" ? "active" : ""}
            onClick={() => setTab("sample")}
          >
            Sample
          </button>
        </div>

        <div className="ds-body">
          {tab === "terraform" && (
            <>
              <p className="ds-note">
                Upload or paste a <code>.tfstate</code> JSON file. No credentials
                involved — it's parsed into a graph and nothing is stored.
              </p>
              <input
                type="file"
                accept=".json,.tfstate,application/json"
                onChange={(e) => onFile(e.target.files?.[0])}
              />
              <textarea
                className="ds-textarea"
                placeholder="…or paste terraform state JSON here"
                value={tfText}
                onChange={(e) => setTfText(e.target.value)}
              />
              <button
                type="button"
                className="ds-primary"
                disabled={busy || !tfText.trim()}
                onClick={() => loadTerraformText(tfText)}
              >
                {busy ? "Loading…" : "Build map from pasted state"}
              </button>
            </>
          )}

          {tab === "live" && (
            <>
              <p className="ds-note">
                Read-only discovery. Credentials are sent once over TLS and{" "}
                <strong>never stored</strong>. Prefer short-lived STS session
                tokens. The role needs no <code>secretsmanager:GetSecretValue</code>
                — kumomiru never reads secret values.{" "}
                <a
                  href={leastPrivilegePolicyUrl}
                  download="kumomiru-readonly-policy.json"
                >
                  Download the exact read-only IAM policy
                </a>
                .
              </p>
              <label className="ds-field">
                <span>Access key ID</span>
                <input
                  value={creds.accessKeyId}
                  autoComplete="off"
                  onChange={(e) =>
                    setCreds({ ...creds, accessKeyId: e.target.value })
                  }
                />
              </label>
              <label className="ds-field">
                <span>Secret access key</span>
                <input
                  type="password"
                  value={creds.secretAccessKey}
                  autoComplete="off"
                  onChange={(e) =>
                    setCreds({ ...creds, secretAccessKey: e.target.value })
                  }
                />
              </label>
              <label className="ds-field">
                <span>Session token (optional)</span>
                <input
                  type="password"
                  value={creds.sessionToken}
                  autoComplete="off"
                  onChange={(e) =>
                    setCreds({ ...creds, sessionToken: e.target.value })
                  }
                />
              </label>
              <label className="ds-field">
                <span>Region</span>
                <input
                  value={creds.region}
                  onChange={(e) => setCreds({ ...creds, region: e.target.value })}
                />
              </label>
              <button
                type="button"
                className="ds-primary"
                disabled={
                  busy ||
                  !creds.accessKeyId.trim() ||
                  !creds.secretAccessKey.trim() ||
                  !creds.region.trim()
                }
                onClick={loadLive}
              >
                {busy ? "Discovering…" : "Discover"}
              </button>
            </>
          )}

          {tab === "sample" && (
            <>
              <p className="ds-note">
                Reload the built-in sample environment — a small AWS account that
                exercises all three lenses and two findings.
              </p>
              <button
                type="button"
                className="ds-primary"
                disabled={busy}
                onClick={loadSample}
              >
                {busy ? "Loading…" : "Load sample"}
              </button>
            </>
          )}

          {error && <p className="ds-error">{error}</p>}
        </div>
      </div>
    </div>
  );
}
