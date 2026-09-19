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
  // S3 bucket — a bucket silhouette.
  "aws::s3::bucket":
    '<path d="M5 6 L7 19.5 H17 L19 6" fill="none" stroke="COL" stroke-width="1.8" stroke-linejoin="round"/><ellipse cx="12" cy="6" rx="7" ry="2.2" fill="none" stroke="COL" stroke-width="1.8"/><line x1="7.5" y1="12.5" x2="16.5" y2="12.5" stroke="COL" stroke-width="1.4"/>',
  // KMS key — a key.
  "aws::kms::key":
    '<circle cx="8" cy="12" r="3.5" fill="none" stroke="COL" stroke-width="1.8"/><line x1="11.5" y1="12" x2="20" y2="12" stroke="COL" stroke-width="1.8"/><line x1="17" y1="12" x2="17" y2="15" stroke="COL" stroke-width="1.8"/><line x1="19.5" y1="12" x2="19.5" y2="14.5" stroke="COL" stroke-width="1.8"/>',
  // EBS volume — a disk.
  "aws::ec2::volume":
    '<ellipse cx="12" cy="8" rx="7" ry="2.6" fill="none" stroke="COL" stroke-width="1.8"/><path d="M5 8 V16 C5 17.4 8.1 18.5 12 18.5 C15.9 18.5 19 17.4 19 16 V8" fill="none" stroke="COL" stroke-width="1.8"/>',
  // EBS snapshot — a disk with a camera-like shutter mark.
  "aws::ec2::snapshot":
    '<ellipse cx="12" cy="9" rx="7" ry="2.4" fill="none" stroke="COL" stroke-width="1.6" stroke-dasharray="3 2"/><path d="M5 9 V15 C5 16.4 8.1 17.5 12 17.5 C15.9 17.5 19 16.4 19 15 V9" fill="none" stroke="COL" stroke-width="1.6" stroke-dasharray="3 2"/>',
  // CloudTrail — a scroll / log.
  "aws::cloudtrail::trail":
    '<rect x="6" y="4" width="12" height="16" rx="1.5" fill="none" stroke="COL" stroke-width="1.8"/><line x1="9" y1="8.5" x2="15" y2="8.5" stroke="COL" stroke-width="1.5"/><line x1="9" y1="12" x2="15" y2="12" stroke="COL" stroke-width="1.5"/><line x1="9" y1="15.5" x2="13" y2="15.5" stroke="COL" stroke-width="1.5"/>',
  // --- Tranche B types (calm line glyphs, same 24×24 convention) ---
  "aws::ec2::route-table":
    '<path d="M5 7 H19 M5 12 H19 M5 17 H19" stroke="COL" stroke-width="1.8"/><path d="M16 4.5 L19 7 L16 9.5 M16 14.5 L19 17 L16 19.5" fill="none" stroke="COL" stroke-width="1.6"/>',
  "aws::ec2::nat-gateway":
    '<rect x="4" y="8" width="16" height="8" rx="2" fill="none" stroke="COL" stroke-width="1.8"/><path d="M8 12 H16 M13 9.5 L16 12 L13 14.5" fill="none" stroke="COL" stroke-width="1.6"/>',
  "aws::ec2::vpc-peering":
    '<circle cx="7" cy="12" r="3" fill="none" stroke="COL" stroke-width="1.8"/><circle cx="17" cy="12" r="3" fill="none" stroke="COL" stroke-width="1.8"/><line x1="10" y1="12" x2="14" y2="12" stroke="COL" stroke-width="1.8"/>',
  "aws::ec2::vpc-endpoint":
    '<circle cx="12" cy="12" r="6.5" fill="none" stroke="COL" stroke-width="1.8"/><circle cx="12" cy="12" r="2" fill="COL"/>',
  "aws::ec2::network-acl":
    '<path d="M12 4 L19 7 V12 C19 16 16 19 12 20.5 C8 19 5 16 5 12 V7 Z" fill="none" stroke="COL" stroke-width="1.8"/><path d="M8.5 12 H15.5" stroke="COL" stroke-width="1.6"/>',
  "aws::elbv2::load-balancer":
    '<circle cx="6" cy="12" r="2.5" fill="none" stroke="COL" stroke-width="1.8"/><circle cx="18" cy="6" r="2.2" fill="none" stroke="COL" stroke-width="1.6"/><circle cx="18" cy="12" r="2.2" fill="none" stroke="COL" stroke-width="1.6"/><circle cx="18" cy="18" r="2.2" fill="none" stroke="COL" stroke-width="1.6"/><path d="M8.5 12 H15.8 M8.5 11.5 L15.8 6.8 M8.5 12.5 L15.8 17.2" fill="none" stroke="COL" stroke-width="1.4"/>',
  "aws::ecs::cluster":
    '<rect x="4" y="4" width="7" height="7" rx="1.2" fill="none" stroke="COL" stroke-width="1.7"/><rect x="13" y="4" width="7" height="7" rx="1.2" fill="none" stroke="COL" stroke-width="1.7"/><rect x="4" y="13" width="7" height="7" rx="1.2" fill="none" stroke="COL" stroke-width="1.7"/><rect x="13" y="13" width="7" height="7" rx="1.2" fill="none" stroke="COL" stroke-width="1.7"/>',
  "aws::ecs::service":
    '<rect x="5" y="6" width="14" height="12" rx="1.8" fill="none" stroke="COL" stroke-width="1.8"/><path d="M9 10 L15 12 L9 14 Z" fill="COL"/>',
  "aws::ecs::task-definition":
    '<rect x="6" y="4" width="12" height="16" rx="1.5" fill="none" stroke="COL" stroke-width="1.8"/><path d="M9 9 H15 M9 12.5 H15 M9 16 H12" stroke="COL" stroke-width="1.5"/>',
  "aws::eks::cluster":
    '<path d="M12 3.5 L19.5 8 V16 L12 20.5 L4.5 16 V8 Z" fill="none" stroke="COL" stroke-width="1.8"/><circle cx="12" cy="12" r="2.2" fill="COL"/>',
  "aws::sqs::queue":
    '<rect x="3.5" y="9" width="4" height="6" rx="1" fill="none" stroke="COL" stroke-width="1.6"/><rect x="10" y="9" width="4" height="6" rx="1" fill="none" stroke="COL" stroke-width="1.6"/><rect x="16.5" y="9" width="4" height="6" rx="1" fill="none" stroke="COL" stroke-width="1.6"/>',
  "aws::sns::topic":
    '<circle cx="7" cy="12" r="2.5" fill="COL"/><path d="M9.5 12 L16 7 M9.5 12 L16 12 M9.5 12 L16 17" fill="none" stroke="COL" stroke-width="1.6"/><circle cx="17.5" cy="7" r="1.6" fill="COL"/><circle cx="17.5" cy="12" r="1.6" fill="COL"/><circle cx="17.5" cy="17" r="1.6" fill="COL"/>',
  "aws::ecr::repository":
    '<path d="M12 4 L19 8 V16 L12 20 L5 16 V8 Z" fill="none" stroke="COL" stroke-width="1.8"/><path d="M5 8 L12 12 L19 8 M12 12 V20" fill="none" stroke="COL" stroke-width="1.5"/>',
  "aws::autoscaling::group":
    '<rect x="4" y="9" width="5" height="6" rx="1" fill="none" stroke="COL" stroke-width="1.6"/><rect x="9.5" y="9" width="5" height="6" rx="1" fill="none" stroke="COL" stroke-width="1.6"/><rect x="15" y="9" width="5" height="6" rx="1" fill="none" stroke="COL" stroke-width="1.6" stroke-dasharray="2 1.5"/><path d="M6 5 L8 3 L10 5 M14 19 L16 21 L18 19" fill="none" stroke="COL" stroke-width="1.5"/>',
  "aws::ec2::launch-template":
    '<rect x="6" y="4" width="12" height="16" rx="1.5" fill="none" stroke="COL" stroke-width="1.8" stroke-dasharray="3 2"/><path d="M9 9 H15 M9 12.5 H15" stroke="COL" stroke-width="1.5"/>',
  "aws::efs::file-system":
    '<path d="M4 7 H10 L12 9 H20 V18 H4 Z" fill="none" stroke="COL" stroke-width="1.8" stroke-linejoin="round"/>',
  "aws::cloudfront::distribution":
    '<circle cx="12" cy="12" r="7.5" fill="none" stroke="COL" stroke-width="1.8"/><path d="M4.5 12 H19.5 M12 4.5 C9 8 9 16 12 19.5 M12 4.5 C15 8 15 16 12 19.5" fill="none" stroke="COL" stroke-width="1.4"/>',
  "aws::apigateway::rest-api":
    '<path d="M8 5 L4 12 L8 19 M16 5 L20 12 L16 19" fill="none" stroke="COL" stroke-width="1.8"/><path d="M10 15 L14 9" stroke="COL" stroke-width="1.6"/>',
  "aws::rds::db-cluster":
    '<ellipse cx="9" cy="7" rx="5" ry="1.8" fill="none" stroke="COL" stroke-width="1.6"/><path d="M4 7 V14 C4 15 6.2 15.8 9 15.8 C11.8 15.8 14 15 14 14 V7" fill="none" stroke="COL" stroke-width="1.6"/><ellipse cx="15" cy="10" rx="5" ry="1.8" fill="none" stroke="COL" stroke-width="1.6"/><path d="M10 10 V17 C10 18 12.2 18.8 15 18.8 C17.8 18.8 20 18 20 17 V10" fill="none" stroke="COL" stroke-width="1.6"/>',
  "aws::rds::db-snapshot":
    '<ellipse cx="12" cy="7" rx="7" ry="2.4" fill="none" stroke="COL" stroke-width="1.6" stroke-dasharray="3 2"/><path d="M5 7 V17 C5 18.4 8.1 19.5 12 19.5 C15.9 19.5 19 18.4 19 17 V7" fill="none" stroke="COL" stroke-width="1.6" stroke-dasharray="3 2"/>',
  "aws::ssm::parameter":
    '<rect x="5.5" y="10.5" width="13" height="9" rx="1.8" fill="none" stroke="COL" stroke-width="1.6" stroke-dasharray="3 2"/><path d="M8 10.5 V8 a4 4 0 0 1 8 0 v2.5" fill="none" stroke="COL" stroke-width="1.6"/>',
  // Secrets Manager — a padlock.
  "aws::secretsmanager::secret":
    '<rect x="5.5" y="10.5" width="13" height="9" rx="1.8" fill="none" stroke="COL" stroke-width="1.8"/><path d="M8 10.5 V8 a4 4 0 0 1 8 0 v2.5" fill="none" stroke="COL" stroke-width="1.8"/><circle cx="12" cy="14.5" r="1.5" fill="COL"/><line x1="12" y1="15.5" x2="12" y2="17.5" stroke="COL" stroke-width="1.6"/>',
  // IAM role — a shield with a check.
  "aws::iam::role":
    '<path d="M12 3.5 L19 6 V11 C19 15.6 16 18.8 12 20.5 C8 18.8 5 15.6 5 11 V6 Z" fill="none" stroke="COL" stroke-width="1.8"/><path d="M9 11.5 L11.2 13.7 L15.2 9.2" fill="none" stroke="COL" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  // IAM user — a person (head + shoulders).
  "aws::iam::user":
    '<circle cx="12" cy="8" r="3.4" fill="none" stroke="COL" stroke-width="1.8"/><path d="M5.5 19 a6.5 6.5 0 0 1 13 0" fill="none" stroke="COL" stroke-width="1.8" stroke-linecap="round"/>',
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
  "aws::iam::user": "#4f46e5",
  "aws::iam::external-principal": "#be123c",
  "aws::ec2::internet-gateway": "#059669",
  "aws::ec2::security-group": "#475569",
  "aws::s3::bucket": "#15803d",
  "aws::kms::key": "#a16207",
  "aws::ec2::volume": "#0284c7",
  "aws::ec2::snapshot": "#0369a1",
  "aws::cloudtrail::trail": "#7e22ce",
  "aws::ec2::route-table": "#64748b",
  "aws::ec2::nat-gateway": "#0d9488",
  "aws::ec2::vpc-peering": "#0891b2",
  "aws::ec2::vpc-endpoint": "#0e7490",
  "aws::ec2::network-acl": "#475569",
  "aws::elbv2::load-balancer": "#8b5cf6",
  "aws::ecs::cluster": "#f59e0b",
  "aws::ecs::service": "#f97316",
  "aws::ecs::task-definition": "#fb923c",
  "aws::eks::cluster": "#f59e0b",
  "aws::sqs::queue": "#ec4899",
  "aws::sns::topic": "#db2777",
  "aws::ecr::repository": "#ea580c",
  "aws::autoscaling::group": "#d97706",
  "aws::ec2::launch-template": "#b45309",
  "aws::efs::file-system": "#16a34a",
  "aws::cloudfront::distribution": "#7c3aed",
  "aws::apigateway::rest-api": "#6d28d9",
  "aws::rds::db-cluster": "#2563eb",
  "aws::rds::db-snapshot": "#1d4ed8",
  "aws::ssm::parameter": "#dc2626",
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
