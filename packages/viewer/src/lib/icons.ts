/**
 * Inline SVG glyphs per AWS resource type, encoded as `data:` URIs for use as
 * Cytoscape `background-image`. The thesis (DESIGN.md §1, §7) is that the map
 * should "read like a real architecture diagram" — a plain rounded rectangle
 * per resource does not; a recognizable glyph does. We deliberately ship small,
 * calm, monochrome line glyphs (tinted to each type's accent) rather than the
 * full official AWS icon set: zero asset pipeline, crisp at any zoom, and
 * visually coherent.
 *
 * Each glyph is authored on a 24×24 viewBox with `stroke`/`fill` set to the
 * type accent so the icon and the node's border read as one color family.
 */

/** 24×24 SVG bodies (no <svg> wrapper). `COL` is replaced with the accent. */
const GLYPHS: Record<string, string> = {
  // EC2 instance — a server/monitor with rack lines.
  "aws::ec2::instance":
    '<rect x="4" y="5" width="16" height="14" rx="2" fill="none" stroke="COL" stroke-width="1.8"/><line x1="7" y1="9" x2="14" y2="9" stroke="COL" stroke-width="1.6"/><line x1="7" y1="12" x2="14" y2="12" stroke="COL" stroke-width="1.6"/><circle cx="16.5" cy="9" r="0.9" fill="COL"/><circle cx="16.5" cy="12" r="0.9" fill="COL"/>',
  // RDS database — a cylinder.
  "aws::rds::db-instance":
    '<ellipse cx="12" cy="6.5" rx="7" ry="2.6" fill="none" stroke="COL" stroke-width="1.8"/><path d="M5 6.5 V17.5 C5 18.9 8.1 20 12 20 C15.9 20 19 18.9 19 17.5 V6.5" fill="none" stroke="COL" stroke-width="1.8"/><path d="M5 12 C5 13.4 8.1 14.5 12 14.5 C15.9 14.5 19 13.4 19 12" fill="none" stroke="COL" stroke-width="1.5"/>',
  // Lambda — the λ glyph.
  "aws::lambda::function":
    '<path d="M6 19 L11 5 H13.5 L18 19 H15.4 L12.1 8.7 L9 19 Z" fill="COL"/>',
  // DynamoDB — a stacked database.
  "aws::dynamodb::table":
    '<ellipse cx="12" cy="6" rx="7" ry="2.4" fill="none" stroke="COL" stroke-width="1.7"/><path d="M5 6 V18 C5 19.3 8.1 20.3 12 20.3 C15.9 20.3 19 19.3 19 18 V6" fill="none" stroke="COL" stroke-width="1.7"/><path d="M5 10 C5 11.3 8.1 12.3 12 12.3 C15.9 12.3 19 11.3 19 10" fill="none" stroke="COL" stroke-width="1.4"/><path d="M5 14 C5 15.3 8.1 16.3 12 16.3 C15.9 16.3 19 15.3 19 14" fill="none" stroke="COL" stroke-width="1.4"/>',
  // Secrets Manager — a padlock.
  "aws::secretsmanager::secret":
    '<rect x="5.5" y="10.5" width="13" height="9" rx="1.8" fill="none" stroke="COL" stroke-width="1.8"/><path d="M8 10.5 V8 a4 4 0 0 1 8 0 v2.5" fill="none" stroke="COL" stroke-width="1.8"/><circle cx="12" cy="14.5" r="1.5" fill="COL"/><line x1="12" y1="15.5" x2="12" y2="17.5" stroke="COL" stroke-width="1.6"/>',
  // IAM role — a shield with a check.
  "aws::iam::role":
    '<path d="M12 3.5 L19 6 V11 C19 15.6 16 18.8 12 20.5 C8 18.8 5 15.6 5 11 V6 Z" fill="none" stroke="COL" stroke-width="1.8"/><path d="M9 11.5 L11.2 13.7 L15.2 9.2" fill="none" stroke="COL" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  // External principal — a globe (the IAM analog of internet exposure).
  "aws::iam::external-principal":
    '<circle cx="12" cy="12" r="8" fill="none" stroke="COL" stroke-width="1.8"/><ellipse cx="12" cy="12" rx="3.4" ry="8" fill="none" stroke="COL" stroke-width="1.5"/><line x1="4" y1="12" x2="20" y2="12" stroke="COL" stroke-width="1.5"/><line x1="5.2" y1="8" x2="18.8" y2="8" stroke="COL" stroke-width="1.2"/><line x1="5.2" y1="16" x2="18.8" y2="16" stroke="COL" stroke-width="1.2"/>',
  // Internet gateway — a cloud with a bidirectional arrow.
  "aws::ec2::internet-gateway":
    '<path d="M7 16 a3.2 3.2 0 0 1 .3 -6.3 a4.3 4.3 0 0 1 8.3 -.6 a3 3 0 0 1 .9 5.9 Z" fill="none" stroke="COL" stroke-width="1.7"/><path d="M9.5 19.5 H14.5 M9.5 19.5 L11 18 M9.5 19.5 L11 21 M14.5 19.5 L13 18 M14.5 19.5 L13 21" fill="none" stroke="COL" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
  // Security group — a brick wall / firewall.
  "aws::ec2::security-group":
    '<rect x="4.5" y="6" width="15" height="12" rx="1.5" fill="none" stroke="COL" stroke-width="1.7"/><line x1="4.5" y1="10" x2="19.5" y2="10" stroke="COL" stroke-width="1.4"/><line x1="4.5" y1="14" x2="19.5" y2="14" stroke="COL" stroke-width="1.4"/><line x1="10" y1="6" x2="10" y2="10" stroke="COL" stroke-width="1.4"/><line x1="14" y1="10" x2="14" y2="14" stroke="COL" stroke-width="1.4"/><line x1="9" y1="14" x2="9" y2="18" stroke="COL" stroke-width="1.4"/>',
};

/** Accent color per type — kept in sync with the stylesheet's RESOURCE_ACCENT. */
const ICON_COLOR: Record<string, string> = {
  "aws::ec2::instance": "#d97706",
  "aws::rds::db-instance": "#2563eb",
  "aws::lambda::function": "#ea580c",
  "aws::dynamodb::table": "#1d4ed8",
  "aws::secretsmanager::secret": "#dc2626",
  "aws::iam::role": "#7c3aed",
  "aws::iam::external-principal": "#be123c",
  "aws::ec2::internet-gateway": "#059669",
  "aws::ec2::security-group": "#475569",
};

/** Wrap a glyph body in an <svg> and encode it as a data URI. */
function dataUri(body: string, color: string): string {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">${body.replace(
    /COL/g,
    color,
  )}</svg>`;
  // encodeURIComponent keeps the SVG valid inside a url(...) without base64.
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

/** type → data-URI icon, for every type that has a glyph. */
export const NODE_ICONS: Record<string, string> = Object.fromEntries(
  Object.keys(GLYPHS).map((type) => [
    type,
    dataUri(GLYPHS[type]!, ICON_COLOR[type] ?? "#475569"),
  ]),
);
