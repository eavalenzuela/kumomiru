import type { StylesheetStyle } from "cytoscape";

/**
 * Cytoscape stylesheet. The goal is "reads like an architecture diagram," not a
 * force-directed hairball: compound containers are soft tinted boxes with their
 * label pinned to the top-left, leaf resources are clean rounded chips, and the
 * network lens emphasizes internet-facing exposure in red.
 *
 * Per-type accent colors are kept deliberately small and calm; AWS service
 * icons can be layered on later via `background-image`.
 */

// Container tints by depth-ish type.
const CONTAINER_COLORS: Record<string, string> = {
  "aws::account": "#eef2ff",
  "aws::region": "#f1f5f9",
  "aws::ec2::vpc": "#ecfeff",
  "aws::ec2::subnet": "#f0fdf4",
};

const RESOURCE_ACCENT: Record<string, string> = {
  "aws::ec2::instance": "#f59e0b",
  "aws::rds::db-instance": "#3b82f6",
  "aws::lambda::function": "#f97316",
  "aws::dynamodb::table": "#2563eb",
  "aws::secretsmanager::secret": "#dc2626",
  "aws::iam::role": "#7c3aed",
  "aws::iam::external-principal": "#be123c",
  "aws::ec2::internet-gateway": "#10b981",
  "aws::ec2::security-group": "#64748b",
};

export function buildStylesheet(): StylesheetStyle[] {
  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        "font-size": 11,
        color: "#0f172a",
        "text-valign": "center",
        "text-halign": "center",
        "border-width": 1.5,
        "border-color": "#cbd5e1",
        "background-color": "#ffffff",
        shape: "round-rectangle",
        width: "label",
        height: 28,
        padding: "8px",
      },
    },
    // Per-type accent: a left color bar via border on leaf resources.
    ...Object.entries(RESOURCE_ACCENT).map(([type, color]) => ({
      selector: `node[kind = "${type}"]`,
      style: {
        "border-color": color,
        "border-width": 2,
      },
    })),
    // Compound containers: tinted boxes, label top-left, room for children.
    {
      selector: "node[?container]",
      style: {
        shape: "round-rectangle",
        "background-opacity": 0.5,
        "text-valign": "top",
        "text-halign": "center",
        "font-size": 12,
        "font-weight": 600,
        color: "#334155",
        "border-color": "#94a3b8",
        "border-width": 1,
        padding: "18px",
      },
    },
    ...Object.entries(CONTAINER_COLORS).map(([type, color]) => ({
      selector: `node[kind = "${type}"]`,
      style: { "background-color": color },
    })),
    // Edges.
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": "#94a3b8",
        "target-arrow-color": "#94a3b8",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        "arrow-scale": 0.9,
        label: "data(label)",
        "font-size": 8,
        color: "#64748b",
        "text-background-color": "#ffffff",
        "text-background-opacity": 0.85,
        "text-background-padding": "2px",
      },
    },
    // Internet-facing ingress: the thing the network lens exists to surface.
    {
      selector: "edge[?internetFacing]",
      style: {
        "line-color": "#dc2626",
        "target-arrow-color": "#dc2626",
        width: 2.5,
        "line-style": "solid",
      },
    },
    // Dim everything not in the active lens (class toggled at runtime).
    {
      selector: ".dimmed",
      style: { opacity: 0.08 },
    },
    {
      selector: "node.dimmed",
      style: { "text-opacity": 0 },
    },
    // Search: fade non-matches, ring the matches. Layered over lens dimming.
    {
      selector: ".search-miss",
      style: { opacity: 0.1 },
    },
    {
      selector: "node.search-hit",
      style: {
        "border-color": "#f59e0b",
        "border-width": 3,
        "background-color": "#fffbeb",
      },
    },
    // Collapse/expand (hand-rolled): a collapsed container's descendants are
    // hidden so the compound parent shrinks to a chip with a dashed border.
    {
      selector: ".collapsed-hidden",
      style: { display: "none" },
    },
    {
      selector: "node.collapsed",
      style: {
        "border-style": "dashed",
        "border-width": 2,
        "text-valign": "center",
        "background-opacity": 0.8,
        padding: "10px",
      },
    },
  ];
}
