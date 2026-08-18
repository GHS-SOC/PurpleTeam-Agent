# Security Policy

## Reporting a vulnerability

**Please do not open a public issue** for a vulnerability, a leaked credential, or anything
that would expose tenant configuration — including someone else's, if you come across it in
a fork or a pull request.

Mail either of these instead, and we will get back to you:

- **fabazari@ghsystems.com**
- **kghanta@ghsystems.com**

Include:

- what you found and where — file and line, or steps to reproduce
- what it would let an attacker do
- whether you think it is already being exploited

## What is in scope

This project generates synthetic Windows telemetry and sends it to Google SecOps
(Chronicle) over its REST API. The things most worth reporting:

- **Anything that lets unmarked data reach a tenant.** Every generated event carries a
  `PT-LAB-<run_id>` marker so analysts can filter it out. Synthetic data without that
  marker is indistinguishable from a real intrusion, and someone will work it as one.
- **Anything that widens the write surface.** `secops_rest._ALLOWED` permits exactly one
  non-GET request, the confirmed log import. A path that reaches Chronicle outside that
  allowlist is a serious finding, and it counts even when the caller holds legitimate
  credentials — that is the case the allowlist exists for.
- **Injection into a filesystem path, shell command, or query** from model- or
  user-supplied input.
- **Standard web and API issues** in `server.py`, the FastAPI app used for the browser UI.

## What is not in scope

- Findings whose only path to impact is an attacker who has already **stolen** valid
  credentials to the tenant. At that point they have far more direct options than this
  project offers.
- Denial of service against an instance you run yourself.
