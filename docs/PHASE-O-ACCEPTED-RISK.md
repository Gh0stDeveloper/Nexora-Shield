# Phase O — Accepted Risk Policy

## Purpose

Accepted risk exists only to document a deliberately deferred **non-release-blocking P2** issue when remediation is not required for the current stable release.

It is not a mechanism for bypassing security, production-path, legal, compatibility or supply-chain gates.

## Prohibited acceptance

The following can never be accepted while Phase O is open:

- any P0 finding;
- any P1 finding;
- any finding marked `releaseRequired: true`;
- any open finding that can invalidate a product/security claim;
- any open finding that can allow stable publication from unapproved code;
- any open finding that can expose signing credentials, user data or build-host integrity;
- any missing legal permission/license required for distribution.

## Eligible acceptance

A finding is eligible only when all are true:

- severity is P2;
- `releaseRequired` is false;
- the finding does not alter the truth of a security or compatibility claim;
- compensating controls exist;
- a named owner is responsible;
- approval is explicit;
- the acceptance expires on a concrete date;
- the accepted risk is re-reviewed in O.14.

## Required record fields

Every accepted risk must record:

- `findingId`;
- `rationale`;
- `owner`;
- `approvedBy`;
- `approvedAt`;
- `expiresAt`;
- `compensatingControls`.

Accepted risks are stored in `release/phase-o-accepted-risks.json`.

## O.0 state

The accepted-risk register starts empty.

This is intentional: all currently inventoried P0/P1 findings are prohibited from acceptance, and the two initial P2 findings are release-required.
