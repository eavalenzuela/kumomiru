import type { StylesheetStyle } from "cytoscape";
import { NODE_ICONS } from "./icons.js";

/**
 * Cytoscape stylesheet. The goal is "reads like an architecture diagram," not a
 * force-directed hairball: compound containers are soft tinted boxes with their
 * label pinned to the top, leaf resources are clean chips with a recognizable
 * resource glyph on top and the name below, and the network lens emphasizes
 * internet-facing exposure in red.
 *
 * Per-type accent colors are kept deliberately small and calm; resource glyphs
 * (see icons.ts) are layered on via `background-image`.
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
  "aws::iam::user": "#6366f1",
  "aws::iam::external-principal": "#be123c",
  "aws::ec2::internet-gateway": "#10b981",
  "aws::ec2::security-group": "#64748b",
  "aws::s3::bucket": "#16a34a",
  "aws::kms::key": "#ca8a04",
  "aws::ec2::volume": "#0ea5e9",
  "aws::ec2::snapshot": "#0284c7",
  "aws::cloudtrail::trail": "#9333ea",
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
    // Leaf resources: a recognizable glyph on top, the name below. This is what
    // makes the map read like an architecture diagram instead of a box-and-line
    // wireframe.
    {
      selector: "node[!container]",
      style: {
        height: 50,
        "min-width": "72px",
        "text-valign": "bottom",
        "text-margin-y": -9,
        "text-max-width": "130px",
        "text-wrap": "ellipsis",
        "font-size": 11,
        "background-color": "#ffffff",
        "background-opacity": 1,
        "background-image": "none",
        "background-fit": "none",
        "background-clip": "none",
        "background-width": "22px",
        "background-height": "22px",
        "background-position-x": "50%",
        "background-position-y": "6px",
        padding: "6px",
      },
    },
    // Per-type accent: border color on leaf resources.
    ...Object.entries(RESOURCE_ACCENT).map(([type, color]) => ({
      selector: `node[kind = "${type}"]`,
      style: {
        "border-color": color,
        "border-width": 2,
      },
    })),
    // Per-type resource glyph (background image).
    ...Object.entries(NODE_ICONS).map(([type, uri]) => ({
      selector: `node[kind = "${type}"]`,
      style: { "background-image": uri },
    })),
    // Security findings on the canvas (DESIGN.md §6): a node that is the subject
    // of a critical/high finding gets a danger halo so the risk is visible on
    // the map, not just in the sidebar. Placed after the per-type accent so it
    // wins on the border.
    {
      selector: 'node[sev = "critical"]',
      style: {
        "underlay-color": "#dc2626",
        "underlay-opacity": 0.25,
        "underlay-padding": 12,
        "border-color": "#dc2626",
        "border-width": 2.5,
      },
    },
    {
      selector: 'node[sev = "high"]',
      style: {
        "underlay-color": "#ea580c",
        "underlay-opacity": 0.2,
        "underlay-padding": 9,
      },
    },
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
    // Edges. Base style; per-lens color follows so each lens reads distinctly.
    {
      selector: "edge",
      style: {
        width: 1.6,
        "line-color": "#94a3b8",
        "target-arrow-color": "#94a3b8",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        "arrow-scale": 0.95,
        label: "data(label)",
        "font-size": 8,
        color: "#475569",
        "text-background-color": "#ffffff",
        "text-background-opacity": 0.9,
        "text-background-padding": "2px",
        "text-rotation": "autorotate",
      },
    },
    // Per-lens edge color: network = slate (observed facts), iam = violet
    // (matches the role accent), dataflow = cyan + dashed (data "in motion").
    {
      selector: 'edge[lens = "network"]',
      style: { "line-color": "#475569", "target-arrow-color": "#475569" },
    },
    {
      selector: 'edge[lens = "iam"]',
      style: { "line-color": "#7c3aed", "target-arrow-color": "#7c3aed" },
    },
    {
      selector: 'edge[lens = "dataflow"]',
      style: {
        "line-color": "#0891b2",
        "target-arrow-color": "#0891b2",
        "line-style": "dashed",
        "line-dash-pattern": [6, 3],
      },
    },
    // Exposure edges — internet-facing ingress and access from an external
    // principal — are the two things kumomiru exists to surface. Bold red in
    // whatever lens they appear, overriding the per-lens color above.
    {
      selector: "edge[?internetFacing], edge[?external]",
      style: {
        "line-color": "#dc2626",
        "target-arrow-color": "#dc2626",
        width: 2.6,
        "line-style": "solid",
        color: "#b91c1c",
        "font-weight": 700,
      },
    },
    // Edges outside the active lens are hidden, so only the active lens's
    // relationships are drawn (class toggled at runtime).
    {
      selector: "edge.lens-off",
      style: { display: "none" },
    },
    // Leaf resources with no edge in the active lens: recessed but still
    // legible — context, not a faint empty ghost box.
    {
      selector: "node.lens-muted",
      style: {
        opacity: 0.4,
        "border-color": "#cbd5e1",
        "background-image-opacity": 0.45,
        // An off-lens node is context, so don't shout its finding here.
        "underlay-opacity": 0,
      },
    },
    // Selection: ring the selected node and emphasize its neighborhood ("what
    // does this touch?"). Emphasis only — nothing is faded — so it composes with
    // lens muting and search instead of fighting over opacity.
    {
      selector: "node.sel",
      style: {
        "overlay-color": "#0ea5e9",
        "overlay-opacity": 0.18,
        "overlay-padding": 8,
        "border-color": "#0284c7",
        "border-width": 3,
        "z-index": 100,
      },
    },
    {
      selector: "node.sel-adj",
      style: {
        "border-color": "#0ea5e9",
        "border-width": 2.5,
        "z-index": 50,
      },
    },
    {
      selector: "edge.sel-adj",
      style: {
        width: 3,
        opacity: 1,
        "z-index": 50,
      },
    },
    // Reverse-reachability spotlight ("who can reach this?"). The reachable set
    // is ringed in sky blue; everything else fades back.
    {
      selector: ".trace-faded",
      style: { opacity: 0.1 },
    },
    {
      selector: "node.trace",
      style: {
        "border-color": "#0284c7",
        "border-width": 3,
        "underlay-color": "#0ea5e9",
        "underlay-opacity": 0.18,
        "underlay-padding": 8,
        "z-index": 80,
      },
    },
    {
      selector: "edge.trace",
      style: {
        "line-color": "#0ea5e9",
        "target-arrow-color": "#0ea5e9",
        width: 3,
        opacity: 1,
        "z-index": 80,
      },
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
        "background-opacity": 0.85,
        padding: "10px",
        // A collapsed compound has all descendants hidden, so it has no children
        // to size from. Give it an explicit minimum so it renders as a readable
        // chip instead of collapsing to a degenerate point.
        "min-width": "120px",
        "min-height": "40px",
      },
    },
  ];
}
