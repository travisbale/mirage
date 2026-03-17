/*
Package aitm defines the central domain model for the mirage AiTM proxy.

It contains no business logic of its own — the proxy pipeline, API, and
storage layers all depend on this package, so keeping it free of outward
dependencies prevents import cycles.

# Phishlet types

[Phishlet] is the unified type representing a phishlet. It combines two
groups of fields that have different lifecycles:

  - Compiled rules (ProxyHosts, SubFilters, AuthTokens, etc.) are populated
    by the phishlet loader from the YAML file. They are never persisted.

  - Operator config (Hostname, BaseDomain, Enabled, Hidden, etc.) is
    persisted to the database and survives restarts.

Either group may be zero-valued. A freshly loaded YAML has no operator
config; a record loaded from the database has no compiled rules. The daemon
merges both at startup and on every YAML reload.

# Lures

A [Lure] is a configured phishing URL tied to a phishlet. It carries
per-lure settings (redirect URL, user-agent filter, OpenGraph tags,
pause schedule) and a 32-byte AES-256-GCM key used to encrypt custom
parameters embedded in the phishing URL's ?p= query value.

# Session lifecycle

A [Session] is created when a victim first hits a lure. It progresses
through three observable states, each of which publishes an event to
the [eventBus]:

 1. Created   — [EventSessionCreated]    — victim loaded the phishing page
 2. Creds     — [EventCredsCaptured]     — username/password captured from a POST
 3. Completed — [EventSessionCompleted]  — all required auth tokens captured;
    [Session.CompletedAt] is set and the post-capture redirect fires

The proxy pipeline calls [SessionService.IsComplete] after every response
to check whether all non-always [TokenRule] entries in the [Phishlet]
have been satisfied. When they have, [SessionService.Complete] marks the
session done and publishes [EventSessionCompleted].

# Event bus

[eventBus] is the publish/subscribe interface that decouples the proxy
pipeline from other components. The WebSocket hub subscribes to
[EventSessionCompleted] to fan the redirect URL out to waiting browsers.
Publish must never block; if a subscriber's channel is full the event is
silently dropped to avoid stalling the proxy hot path.
*/
package aitm
