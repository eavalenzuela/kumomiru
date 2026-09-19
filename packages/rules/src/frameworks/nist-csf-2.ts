import type { Catalogue } from "./types.js";

/**
 * NIST Cybersecurity Framework 2.0 — the subcategories kumomiru rules map to.
 * AWS publishes no CSF 2.0 mapping (Security Hub maps to SP 800-53), so this
 * mapping is authored and versioned here. Ids follow the CSF 2.0 core
 * (Function.Category-NN).
 */
export const NIST_CSF_2: Catalogue = {
  framework: "nist-csf-2",
  name: "NIST Cybersecurity Framework 2.0",
  version: "2026-09",
  controls: [
    { id: "ID.AM-01", title: "Inventories of hardware managed by the organization are maintained" },
    { id: "ID.AM-02", title: "Inventories of software, services, and systems managed by the organization are maintained" },
    { id: "PR.AA-01", title: "Identities and credentials for authorized users, services, and hardware are managed by the organization" },
    { id: "PR.AA-05", title: "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties" },
    { id: "PR.DS-01", title: "The confidentiality, integrity, and availability of data-at-rest are protected" },
    { id: "PR.DS-02", title: "The confidentiality, integrity, and availability of data-in-transit are protected" },
    { id: "PR.IR-01", title: "Networks and environments are protected from unauthorized logical access and usage" },
    { id: "DE.CM-01", title: "Networks and network services are monitored to find potentially adverse events" },
  ],
};
