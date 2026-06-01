import type { Lens } from "@kumomiru/graph";

const LABELS: Record<Lens, string> = {
  network: "Network",
  iam: "IAM",
  dataflow: "Data flow",
};

interface LensToggleProps {
  lenses: Lens[];
  active: Lens;
  onChange: (lens: Lens) => void;
}

/** Segmented control for switching the active lens. */
export function LensToggle({ lenses, active, onChange }: LensToggleProps) {
  return (
    <div className="lens-toggle" role="tablist" aria-label="Map lens">
      {lenses.map((lens) => (
        <button
          key={lens}
          role="tab"
          aria-selected={lens === active}
          className={lens === active ? "active" : ""}
          onClick={() => onChange(lens)}
        >
          {LABELS[lens]}
        </button>
      ))}
    </div>
  );
}
