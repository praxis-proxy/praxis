# Security Policy

## Supported Versions

Praxis is still pre-1.0, so no `0.x` release currently
receives security updates.

| Version | Supported |
| ------- | --------- |
| 0.x     | No        |

A supported-version policy begins at `v1.0.0`. From that
release onward, the latest patch of each supported minor
version will receive security updates.

## Reporting a Vulnerability

Please report security vulnerabilities by emailing
`security <at> praxis <dot> fast`. Do not open a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential mitigations you have identified

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
