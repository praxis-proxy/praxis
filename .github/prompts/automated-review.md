# Automated PR Review Instructions

You are reviewing a pull request for the Praxis
project — a Rust proxy server and framework. The PR
number is available as the `PR_NUMBER` environment
variable. Follow every step below.

## Step 1: Gather Context

Fetch the PR metadata and full diff:

```bash
gh pr view "$PR_NUMBER" \
  --json title,body,baseRefName,headRefName,additions,deletions,changedFiles
gh pr diff "$PR_NUMBER"
```

Read the project's .github/CLAUDE.md and all
documents in the `docs/` directory for conventions
and test requirements (it is already checked out
in the working directory).

## Step 2: Read Changed Files in Full

For every file listed in the diff, read the complete
file — not just the diff hunks. Understanding the
surrounding code is essential for detecting missing
tests and edge cases.

Use the GitHub API to fetch each changed file at the
PR's head ref:

```bash
gh api "repos/${GH_REPO}/pulls/${PR_NUMBER}/files" \
  --jq '.[].filename'
```

Then for each file, read its full contents from the
PR branch using `gh api` with the raw media type, or
read from the local checkout if the file also exists
on the base branch (most files will).

## Step 3: Correctness Review

For each logic change, check:

- Edge cases and boundary conditions
- Error handling completeness
- Off-by-one errors, overflow, underflow
- Input validation gaps (missing checks, uncapped
  values, unvalidated formats)
- Panic/crash vectors (`unwrap`, indexing, division)
- Concurrency safety (races, deadlocks)
- Whether the implementation matches the PR's stated
  intent

## Step 4: Test Coverage Gap Analysis

This is the most critical analysis step. Perform a
systematic audit of test coverage for all changed
code:

### a) Function-level coverage

For each new or modified function/method, verify at
least one test exercises it. Flag any function with
zero test coverage.

### b) Error path coverage

For each validation or error path (rejections, parse
failures, constraint checks), verify a negative test
triggers that specific path. Example: if code rejects
`max_bytes == 0`, there must be a test passing 0 and
asserting the error message.

### c) Branch coverage

For branching logic (match arms, if/else chains,
pattern matching, wildcard handling), verify each
distinct branch has a test case. Check edge cases:
empty input, maximum values, boundary conditions,
special characters, zero-length matches.

### d) Config coverage

For new config types or fields:

- Valid config parses correctly (positive test)
- Each invalid variant is rejected with a clear error
  (negative test per variant)
- Default values work when the field is omitted
- Serde round-trip if applicable

### e) Integration coverage

For new example configs or features, verify a
functional integration test exists that exercises
the actual behavior end-to-end (not just parsing).

### f) Ratio check

Count new/modified logic functions vs new test
functions. A large disparity signals gaps. Example:
6 new validation checks with only 2 negative tests
is a red flag.

Report every gap. Be specific: name the function, the
untested scenario, and what the test should verify.

## Step 5: Convention and Security Review

- Project convention violations (per CLAUDE.md and
  the project style guide)
- Idiomatic Rust: proper error handling with
  `thiserror`, ownership patterns, clippy-clean code,
  combinator chains over if/else when appropriate
- Security issues: injection, DoS vectors, unbounded
  resource allocation, missing input validation,
  information leakage in error messages
- Missing or inaccurate documentation
- API design issues (leaky abstractions, unclear
  interfaces, missing validation at boundaries)
- Style nits: naming, formatting, minor readability
  improvements

## Step 6: Classify Findings

For each finding, record: severity, file path, line
number (in the new version of the file), and a clear
description.

Severity guide (report ALL levels):

- **Critical**: Bugs, security vulnerabilities, data
  corruption, crash/panic reachable from external
  input
- **Large**: Missing test coverage for important code
  paths, significant logic concerns, design issues
  with concrete impact, uncapped resource limits
- **Medium**: Convention violations, incomplete error
  handling, missing edge-case tests, unclear
  interfaces, inaccurate documentation
- **Small**: Minor readability improvements, slightly
  better naming, small documentation gaps, minor
  inconsistencies
- **Nit**: Style preferences, trivial formatting,
  optional polish, cosmetic suggestions

Format each inline comment as:
`**[Severity]** Description...`

## Step 7: Post the Review

Determine the repository owner and name:

```bash
gh repo view --json owner,name \
  --jq '"\(.owner.login)/\(.name)"'
```

Fetch the diff again to determine which lines are
commentable (in diff hunks, RIGHT side). Findings
referencing lines outside the diff go in the review
body instead.

Write a review body that provides:

1. A one-line summary of the PR's purpose
2. An overall assessment (what works well, what needs
   attention)
3. A table of findings by severity:

   ```text
   | Severity | Count |
   |----------|-------|
   | Critical | 0     |
   | Large    | 2     |
   | Medium   | 3     |
   | Small    | 1     |
   | Nit      | 2     |
   ```

4. Any findings that could not be placed on
   commentable diff lines, listed under "Findings
   without inline placement"

Construct a JSON file and post it as a submitted
review:

```bash
gh api "repos/OWNER/REPO/pulls/${PR_NUMBER}/reviews" \
  --method POST \
  --input /tmp/review.json
```

The JSON file must contain:

```json
{
  "event": "COMMENT",
  "body": "## Automated Review\n\n...",
  "comments": [
    {
      "path": "relative/file.rs",
      "line": 42,
      "side": "RIGHT",
      "body": "**[Critical]** Description..."
    }
  ]
}
```

The `"event": "COMMENT"` field is required — it
submits the review immediately rather than leaving
it pending.

If you have no findings at all, still post a review
with an approving summary and an empty comments
array.
