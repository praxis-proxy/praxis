# Security Policy

## Supported Versions

All `v0.x.x` releases are unsupported. Praxis is currently still
pre-v1, so there are NO supported versions yet.

| Version | Supported |
| ------- | --------- |
| 0.x.x   | No        |

A supported-version policy begins at `v1.0.0`. From that release
onward, the latest patch of each supported minor version will
receive security updates.

Special releases like `v1.x.x-rcx` or any other `vx.x.x-y` tagged
releases are unsupported.

## Reporting a Vulnerability

Please report security vulnerabilities by emailing
`security <at> praxis <dot> fast`. Do not open a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential mitigations you have identified

> **Note** :You can use GitHub's private security reporting tool if
> you prefer.

## Response Timeline

Prior to `v1.0.0` we will work with researchers individually on
timelines. After `v1.0.0` we will have a standardized response timeline.

## Severity Classification

We use the following severity levels:

- **Critical**: Remote code execution, authentication bypass, or data exfiltration without user interaction
- **High**: Denial of service with amplification, privilege escalation, or significant data exposure
- **Medium**: Denial of service requiring sustained effort, information disclosure of limited scope
- **Low**: Issues requiring unlikely configurations or minimal impact

## Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action
against researchers who follow this policy and report findings responsibly. In fact, we really appreciate
the help in making Praxis more secure, thank you for your efforts!
