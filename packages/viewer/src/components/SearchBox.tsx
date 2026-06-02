interface SearchBoxProps {
  value: string;
  onChange: (q: string) => void;
  /** Number of matched nodes for the current query (shown when searching). */
  matches: number;
}

/** Topbar search input; highlighting is applied to the canvas by the parent. */
export function SearchBox({ value, onChange, matches }: SearchBoxProps) {
  return (
    <div className="searchbox">
      <input
        type="search"
        placeholder="Search resources…"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Search resources"
      />
      {value.trim() && (
        <span className="search-count">
          {matches} match{matches === 1 ? "" : "es"}
        </span>
      )}
    </div>
  );
}
