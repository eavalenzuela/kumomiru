import type { Rule } from "../types.js";
import { ec2Rules } from "./ec2.js";
import { rdsRules } from "./rds.js";
import { nativeRules } from "./native.js";
import { iamRules } from "./iam.js";
import { s3Rules } from "./s3.js";
import { storageEncryptionRules } from "./storage-encryption.js";
import { auditRules } from "./audit.js";
import { trancheBRules } from "./tranche-b.js";

export const builtinRules: Rule[] = [
  ...nativeRules,
  ...ec2Rules,
  ...rdsRules,
  ...iamRules,
  ...s3Rules,
  ...storageEncryptionRules,
  ...auditRules,
  ...trancheBRules,
];
