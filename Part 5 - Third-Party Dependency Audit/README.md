# Snyk Critical and High Vulnerability Summary

No critical vulnerabilities were reported. The table below lists the high-severity issues identified by Snyk.

| Package name | Package version | Vulnerability type | Remediation steps |
| --- | --- | --- | --- |
| async | 2.6.0 | Prototype Pollution | Upgrade to 2.6.4, 3.2.2 |
| bson | 1.0.9 | Internal Property Tampering | Upgrade to 1.1.4 |
| lodash | 4.17.10 | Code Injection | Upgrade to 4.17.21 |
| lodash | 4.17.10 | Arbitrary Code Injection | Upgrade to 4.18.1 |
| lodash | 4.17.10 | Prototype Pollution | Upgrade to 4.17.12 |
| mongodb | 2.2.34 | Denial of Service (DoS) | Upgrade to 3.1.13 |
| mongoose | 4.13.21 | Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') | Upgrade to 6.13.9, 7.8.9, 8.22.1, 9.1.6 |
| mongoose | 4.13.21 | Prototype Pollution | Upgrade to 5.13.15, 6.4.6 |
| mongoose | 4.13.21 | Improper Neutralization of Special Elements in Data Query Logic | Upgrade to 6.13.5, 7.8.3, 8.8.3 |
| mquery | 2.3.3 | Prototype Pollution | Upgrade to 3.2.3 |
| qs | 6.3.1 | Allocation of Resources Without Limits or Throttling | Upgrade to 6.14.1 |
| qs | 6.3.1 | Prototype Poisoning | Upgrade to 6.2.4, 6.3.3, 6.4.1, 6.5.3, 6.6.1, 6.7.3, 6.8.3, 6.9.7, 6.10.3 |
| qs | 6.3.1 | Prototype Override Protection Bypass | Upgrade to 6.0.4, 6.1.2, 6.2.3, 6.3.2 |
| fresh | 0.5.0 | Regular Expression Denial of Service (ReDoS) | Upgrade to 0.5.2 |


34 issues can be remediated by upgrading the package.

3 issues are patchable:

1. lodash@4.17.10 Prototype Pollution - "https://snyk-patches.s3.amazonaws.com/npm/lodash/20200430/lodash_0_0_20200430_6baae67d501e4c45021280876d42efe351e77551.patch"
2. lodash@4.17.10 Prototype Pollution - "https://snyk-patches.s3.amazonaws.com/npm/lodash/20200430/lodash_0_0_20200430_6baae67d501e4c45021280876d42efe351e77551.patch"
3. qs@6.3.1 Prototype Override Protection Bypass - "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/630_632.patch"
