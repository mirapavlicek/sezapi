# HSDemo — runnable InterSystems IRIS for Health example

A small but complete application that exercises every area the skill covers, and
is verified by compiling and running its unit tests inside a real IRIS for Health
instance (see `../docker/`).

## What's inside (`src/HSDemo/`)

| Class | Demonstrates |
|---|---|
| `Data/Patient.cls` | `%Persistent` + `%JSON.Adaptor` + `%Populate`, unique & bitmap indices, computed property, `%OnValidateObject` callback, relationship (parent) |
| `Data/Observation.cls` | child side of a parent-child relationship, required typed properties |
| `Service/Registry.cls` | business logic in pure ObjectScript: object API, `MRNIndexOpen`, Dynamic SQL (parameterized), transactions with `Try/Catch` + `$$$ThrowOnError` |
| `Util/Stats.cls` | Embedded Python methods (`[ Language = python ]`), the `iris` module running SQL from Python |
| `REST/API.cls` | `%CSP.REST` JSON API with `XData UrlMap`, `%DynamicObject`, HTTP status codes |
| `Interop/*.cls` | interoperability production: `Ens.Request` message, `Ens.BusinessOperation` with `MessageMap` + File adapter, `Ens.Production` |
| `Tests/RegistryTest.cls` | `%UnitTest.TestCase` covering all of the above with assertion macros |

## Run it

From `../docker/`:

```bash
./run.sh           # starts IRIS for Health (Community), loads + compiles src, runs the unit tests
```

The build fails (non-zero exit) if anything does not compile or a test assertion
fails. See `../docker/README.md` for details, the Management Portal URL, and how
to exercise the REST API and the interoperability production.

## Naming note

The package root is `HSDemo` — **not** `HS` (reserved for HealthShare) or `%`
(reserved for InterSystems libraries). SQL tables project as schema `HSDemo_Data`,
e.g. `HSDemo_Data.Patient`.
