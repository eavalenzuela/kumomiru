import type { CheckRule, RuleOutcome } from "../types.js";
import { coversPort, coversPortOutside, ingressOf, isPublicRule, portLabel, publicCidrs } from "./ingress.js";
import type { IngressRule } from "./ingress.js";

const SG = "aws::ec2::security-group";

function sgFailure(matches: IngressRule[], what: string): RuleOutcome {
  if (matches.length === 0) return { status: "pass" };
  const rules = matches.map((r) => `${r.protocol ?? "all"} ${portLabel(r)} from ${publicCidrs(r).join(",")}`);
  return {
    status: "fail",
    detail: `${what}: ${rules.join("; ")}`,
    evidence: { rules },
  };
}

function publicRulesCovering(node: Parameters<CheckRule["check"]>[0], port: number): IngressRule[] {
  return ingressOf(node).filter((r) => isPublicRule(r) && coversPort(r, port));
}

export const sgUnrestrictedSsh: CheckRule = {
  id: "ec2.sg-unrestricted-ssh",
  version: 1,
  title: "Security group allows SSH (22) from the internet",
  severity: "high",
  kind: "sg-open-ssh",
  resourceTypes: [SG],
  requires: ["ec2:security-group"],
  controls: [
    { framework: "fsbp", id: "EC2.13" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Remove the 0.0.0.0/0 or ::/0 ingress rule for port 22. Reach instances through SSM Session Manager or a bastion restricted to known CIDRs.",
    cli: "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0",
    terraform: 'ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["<your-cidr>/32"]  # not 0.0.0.0/0\n}',
  },
  check: (node) => sgFailure(publicRulesCovering(node, 22), "port 22 open to the internet"),
};

export const sgUnrestrictedRdp: CheckRule = {
  id: "ec2.sg-unrestricted-rdp",
  version: 1,
  title: "Security group allows RDP (3389) from the internet",
  severity: "high",
  kind: "sg-open-rdp",
  resourceTypes: [SG],
  requires: ["ec2:security-group"],
  controls: [
    { framework: "fsbp", id: "EC2.14" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Remove the 0.0.0.0/0 or ::/0 ingress rule for port 3389. Use SSM Session Manager or a bastion restricted to known CIDRs.",
    cli: "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 3389 --cidr 0.0.0.0/0",
  },
  check: (node) => sgFailure(publicRulesCovering(node, 3389), "port 3389 open to the internet"),
};

/** FSBP EC2.19's high-risk port list. */
export const HIGH_RISK_PORTS = [
  20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389, 4333,
  5000, 5432, 5500, 5601, 8080, 8088, 8888, 9200, 9300,
] as const;

export const sgUnrestrictedHighRiskPorts: CheckRule = {
  id: "ec2.sg-unrestricted-high-risk-ports",
  version: 1,
  title: "Security group allows unrestricted access to high-risk ports",
  severity: "critical",
  kind: "sg-open-high-risk-port",
  resourceTypes: [SG],
  requires: ["ec2:security-group"],
  controls: [
    { framework: "fsbp", id: "EC2.19" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Restrict the rule to known source CIDRs or a source security group. Database, admin, and management ports must never be open to 0.0.0.0/0.",
    cli: "aws ec2 revoke-security-group-ingress --group-id <sg-id> --ip-permissions '<the offending permission>'",
  },
  check: (node) => {
    const rules = ingressOf(node).filter(
      (r) => isPublicRule(r) && HIGH_RISK_PORTS.some((p) => coversPort(r, p)),
    );
    const out = sgFailure(rules, "high-risk ports open to the internet");
    if (out.status === "fail") {
      const ports = HIGH_RISK_PORTS.filter((p) => rules.some((r) => coversPort(r, p)));
      out.evidence = { ...out.evidence, ports };
      out.detail = `high-risk ports ${ports.join(", ")} open to the internet`;
    }
    return out;
  },
};

/** Ports FSBP EC2.18 treats as authorized for unrestricted ingress by default. */
export const AUTHORIZED_PUBLIC_PORTS: ReadonlySet<number> = new Set([80, 443]);

export const sgUnrestrictedUnauthorizedPorts: CheckRule = {
  id: "ec2.sg-unrestricted-unauthorized-ports",
  version: 1,
  title: "Security group allows unrestricted ingress on ports other than 80/443",
  severity: "high",
  kind: "sg-open-unauthorized-port",
  resourceTypes: [SG],
  requires: ["ec2:security-group"],
  controls: [
    { framework: "fsbp", id: "EC2.18" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Only 80 and 443 should accept traffic from 0.0.0.0/0. Narrow other rules to known CIDRs or a source security group, or put the service behind a load balancer.",
  },
  check: (node) =>
    sgFailure(
      ingressOf(node).filter((r) => isPublicRule(r) && coversPortOutside(r, AUTHORIZED_PUBLIC_PORTS)),
      "unrestricted ingress beyond 80/443",
    ),
};

export const subnetAutoPublicIp: CheckRule = {
  id: "ec2.subnet-auto-assign-public-ip",
  version: 1,
  title: "Subnet auto-assigns public IP addresses",
  severity: "medium",
  kind: "subnet-auto-public-ip",
  resourceTypes: ["aws::ec2::subnet"],
  requires: ["ec2:subnet"],
  controls: [
    { framework: "fsbp", id: "EC2.15" },
    { framework: "nist-csf-2", id: "PR.IR-01" },
  ],
  remediation: {
    text: "Disable MapPublicIpOnLaunch on the subnet and give instances that need to be reachable an explicit Elastic IP or a load balancer.",
    cli: "aws ec2 modify-subnet-attribute --subnet-id <subnet-id> --no-map-public-ip-on-launch",
    terraform: "map_public_ip_on_launch = false",
  },
  check: (node) =>
    node.attributes["mapPublicIpOnLaunch"] === true
      ? { status: "fail", detail: "MapPublicIpOnLaunch is enabled" }
      : { status: "pass" },
};

export const ec2Rules: CheckRule[] = [
  sgUnrestrictedSsh,
  sgUnrestrictedRdp,
  sgUnrestrictedHighRiskPorts,
  sgUnrestrictedUnauthorizedPorts,
  subnetAutoPublicIp,
];
