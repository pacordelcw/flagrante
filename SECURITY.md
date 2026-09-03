# Security policy

There is a particular obligation to get this right here. Flagrante exists to tell
manufacturers when a vulnerability in their product starts a reporting clock, and
the Cyber Resilience Act it is built around requires those manufacturers to run a
coordinated vulnerability disclosure process of their own. A tool making that
argument without one would be arguing against itself.

## Reporting a vulnerability

Email **security@flagrante.dev**, or open a
[private security advisory](https://github.com/pacordelcw/flagrante/security/advisories/new)
on this repository. Please do not open a public issue first.

What helps: what you found, how to reproduce it, and what you think the impact is.
A proof of concept is welcome but not required.

**What to expect.** This is currently maintained by one person, so the honest
commitment is a first reply within 72 hours and an assessment within 7 days. If
that slips, it is a lapse and you are welcome to say so publicly.

Fixes are released as a new version, credited to you unless you prefer otherwise,
and described plainly in the release notes rather than buried.

## What counts

The failure mode that matters most is **a false negative**: Flagrante reporting no
exploitation signal when a component genuinely carries one, or otherwise implying a
manufacturer is in the clear. Over-flagging costs someone an afternoon;
under-flagging can cost them up to €15 million. If you can make it under-report,
that is a security bug in this project even if it is not a security bug anywhere
else.

Also in scope:

- Anything that would cause an uploaded SBOM to be written to disk, logged, cached,
  or transmitted anywhere. The hosted scanner is designed so this cannot happen; if
  it can, we want to know immediately.
- Injection into the generated HTML report, which people are invited to share.
- Anything that lets one visitor read or delete another visitor's stored record.
- Anything that lets the scanner be used to attack a third party.

Out of scope: the accuracy of the upstream feeds themselves (OSV, CISA KEV, FIRST
EPSS), missing findings that those feeds do not carry, and the documented limits in
the README — that we cannot tell whether vulnerable code is reachable in your
product, and that "actively exploited" is not perfectly determinable from public
data.

## Supported versions

The latest release, and only the latest. There is not enough history yet to
backport anything, and pretending otherwise would be theatre.

## This project's own supply chain

Flagrante has **no runtime dependencies**. That is a security property, not an
aesthetic one: there is no transitive tree to audit and nothing that can be
compromised upstream and pulled into your CI through us. Releases are published to
PyPI through GitHub's OIDC trusted publishing, so no long-lived API token exists
that could be stolen and used to publish a malicious version.
