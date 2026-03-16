/*
Package aitm defines the central domain model for the mirage AiTM proxy.

It contains no business logic of its own — the proxy pipeline, API, and
storage layers all depend on this package, so keeping it free of outward
dependencies prevents import cycles.

# Phishlet types

There are three distinct phishlet-related types that are easy to confuse:

  - [PhishletDef] is the compiled, in-memory representation of a phishlet
    YAML file. All regex fields are pre-compiled and template parameters
    have been substituted. It is rebuilt from disk on every reload and is
    never persisted.

  - [PhishletDeployment] is the operator's runtime state for a phishlet:
    the hostname it answers on, whether it is enabled/hidden, and which DNS
    provider manages its records. This is persisted to the database and
    survives restarts.

  - [SubPhishlet] is a named variant of a parent phishlet, created by
    the operator with a specific set of template parameters. Sub-phishlets
    are persisted and generate their own [PhishletDef] on load.

# Lures

A [Lure] is a configured phishing URL tied to a phishlet. It carries
per-lure settings (redirect URL, user-agent filter, OpenGraph tags,
pause schedule) and a 32-byte AES-256-GCM key used to encrypt custom
parameters embedded in the phishing URL's ?p= query value.

# Session lifecycle

A [Session] is created when a victim first hits a lure. It progresses
through three observable states, each of which publishes an event to
the [EventBus]:

 1. Created   — [EventSessionCreated]    — victim loaded the phishing page
 2. Creds     — [EventCredsCaptured]     — username/password captured from a POST
 3. Completed — [EventSessionCompleted]  — all required auth tokens captured;
    [Session.CompletedAt] is set and the post-capture redirect fires

The proxy pipeline calls [SessionService.IsComplete] after every response
to check whether all non-always [TokenRule] entries in the [PhishletDef]
have been satisfied. When they have, [SessionService.Complete] marks the
session done and publishes [EventSessionCompleted].

# Event bus

[EventBus] is the publish/subscribe interface that decouples the proxy
pipeline from other components. The WebSocket hub subscribes to
[EventSessionCompleted] to fan the redirect URL out to waiting browsers.
Publish must never block; if a subscriber's channel is full the event is
silently dropped to avoid stalling the proxy hot path.
*/
package aitm
