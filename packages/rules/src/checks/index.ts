import type { Rule } from "../types.js";
import { ec2Rules } from "./ec2.js";
import { rdsRules } from "./rds.js";
import { nativeRules } from "./native.js";

export const builtinRules: Rule[] = [...nativeRules, ...ec2Rules, ...rdsRules];
