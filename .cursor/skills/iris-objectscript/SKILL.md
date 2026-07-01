---
name: iris-objectscript
description: >-
  Write, review, and refactor code for InterSystems IRIS and IRIS for Health to the
  platform's own standards: ObjectScript, class definitions (.cls), persistent
  objects, InterSystems SQL, Embedded Python, and interoperability productions
  (HL7, FHIR, REST). Use this skill whenever the user is working with ObjectScript,
  .cls / .mac / .int / .inc files, %Persistent or %RegisteredObject classes, the
  iris module, &sql(), %SQL.Statement, Ens.Production / business services /
  processes / operations, DTL, HL7 v2, FHIR repositories, or %CSP.REST — even if
  they don't name "IRIS" explicitly (e.g. "fix this Caché class", "save this object
  to the database", "write a business operation", "%Status error"). Trigger on any
  mention of ObjectScript, InterSystems, IRIS, Caché, Ensemble, HealthShare,
  globals (^Name), $$$OK / $$$ERROR, %New / %Save / %OpenId, or DocBook KEYs.
---

# InterSystems IRIS — ObjectScript & Platform Coding

This skill makes you write IRIS code the way the platform and InterSystems
documentation expect it: idiomatic ObjectScript, correctly structured class
definitions, proper `%Status` error handling, SQL and object access that match,
Embedded Python that interoperates cleanly, and interoperability productions built
from the standard base classes.

Target platform: **InterSystems IRIS / IRIS for Health 2026.1** (the conventions
are stable across recent versions and apply to legacy Caché/Ensemble code too).

## How to use this skill

1. Identify which area the task touches and read the matching reference file
   **before writing code** — the details there are what keep the code correct.
2. Follow the non-negotiable house rules below in every file you produce.
3. Produce real class/routine files (`.cls`, `.mac`, `.inc`) with correct UDL
   syntax — not pseudo-code — unless the user only wants a snippet.
4. When a fact is version- or API-specific and you are unsure, consult the
   official page in `references/doc-map.md` rather than guessing.

### Where to read next

| Task involves… | Read |
|---|---|
| ObjectScript syntax, commands, functions, macros, error handling | `references/objectscript-language.md` |
| Defining classes: properties, methods, parameters, inheritance, callbacks | `references/classes.md` |
| Saving data, indices, storage, embedded/dynamic SQL, class queries, transactions | `references/persistence-and-sql.md` |
| Embedded Python, the `iris` module, calling between languages, Native SDK | `references/embedded-python.md` |
| Productions, business hosts, messages, DTL, HL7, FHIR, REST services | `references/interoperability.md` |
| IHE profiles (XDS.b, XCA, PIX/PDQ), SDA, CDA↔SDA↔FHIR converters, FHIR services | `references/ihe-and-clinical-interop.md` |
| Standard M/MUMPS & legacy routines, raw globals + generated storage globals, debugging compiled `.int` code, error log | `references/mumps-globals-and-debugging.md` |
| Naming, formatting, documentation, file/source layout | `references/naming-and-style.md` |
| Finding the authoritative doc page for any topic | `references/doc-map.md` |

Each reference is self-contained; read only what the task needs.

### Bundled, runnable assets

This skill ships working code and a harness so generated code can actually be
compiled and tested — don't write boilerplate from scratch when an asset exists:

- `assets/example-app/` — a complete, **compilable** IRIS for Health app
  (`HSDemo`): persistent classes, business logic, Dynamic SQL, Embedded Python,
  `%CSP.REST`, an interoperability production, and a `%UnitTest` suite. Read these
  for a known-good pattern; copy and adapt them.
- `assets/templates/` — minimal, valid skeletons for each artifact type
  (persistent/serial class, `%CSP.REST`, unit test, business service/operation,
  BPL process, HL7 DTL, production). Stamp these out with `__PKG__`/`__CLASS__`
  filled in.
- `assets/docker/` — `run.sh` + `docker-compose.yml` that boot IRIS for Health
  Community, compile a source tree, and run the tests (the real correctness gate).
- `scripts/new_project.sh` — scaffold a new project (source tree + tests + harness).
- `scripts/lint_udl.py` — fast structural check of `.cls` files; run it on every
  class you generate before claiming it's done.

---

## House rules (apply to all IRIS code)

These are the conventions that distinguish correct, professional IRIS code from
code that merely compiles. Internalize them.

### 1. Class and file structure

A class is defined in Universal Definition Language (UDL), stored in a `.cls`
file whose path mirrors the class name (`MyApp.Data.Patient` →
`MyApp/Data/Patient.cls`):

```objectscript
Class MyApp.Data.Patient Extends (%Persistent, %JSON.Adaptor)
{

Property MRN As %String(MAXLEN = 20) [ Required ];

Property BirthDate As %Date;

Index MRNIndex On MRN [ Unique ];

/// Returns the patient's age in whole years as of today.
Method GetAge() As %Integer
{
    Quit $System.SQL.DATEDIFF("yyyy", ..BirthDate, $Horolog)
}

}
```

Rules that matter:

- One class per `.cls` file; the file/package path mirrors the dotted class name.
- Members are `Property`, `Method`, `ClassMethod`, `Parameter`, `Index`,
  `ForeignKey`, `Trigger`, `Query`, `Relationship`, `XData`, `Projection`,
  `Storage`. Keywords go in `[ ... ]` brackets after the member signature.
- `Extends` lists superclasses; the **first** superclass determines primary
  inheritance (its storage, its default `$This` behavior). Order matters.
- Let the compiler generate the `Storage` definition for persistent classes —
  do **not** hand-write it unless you are deliberately mapping to existing globals.

See `references/classes.md` for the full member and keyword reference.

### 2. Error handling — `%Status` is the default contract

Most InterSystems library methods return a `%Status` (or `%Library.Status`). Honor it:

```objectscript
Set sc = patient.%Save()
If $$$ISERR(sc) {
    // handle / propagate — never silently ignore
    Quit sc
}
```

- Use the status macros from `%occStatus.inc` (available by default in methods):
  `$$$OK`, `$$$ERROR(code, args...)`, `$$$ISERR(sc)`, `$$$ISOK(sc)`,
  `$$$ADDSC(sc1, sc2)` to combine statuses.
- Prefer `$$$ThrowOnError(sc)` (a standalone statement, no `Set`) to convert a bad
  status into an exception inside a `Try/Catch` block; this is the modern idiom.
- Use `Try { … } Catch ex { Set sc = ex.AsStatus() … }` for exception handling.
  `ex` is an `%Exception.AbstractException`. Avoid the legacy `$ZTRAP`/`$ZError`
  mechanism in new code.
- Define custom errors with `$$$ERROR($$$GeneralError, "message")` or a
  message-dictionary code; return them up the call stack — don't `Write` them.

Full treatment in `references/objectscript-language.md` (Error handling).

### 3. ObjectScript idioms

- Commands are case-insensitive but **write them in PascalCase**: `Set`, `Do`,
  `Write`, `If`, `For`, `While`, `Quit`, `Return`, `Throw`, `New`, `Kill`.
  Reserve abbreviations (`s`, `d`, `w`, `q`) for the terminal, not source files.
- Use **procedure blocks with curly braces** and explicit variable scoping. Avoid
  the legacy dot-syntax (`. Do`) and line-label flow in new code:

  ```objectscript
  ClassMethod Process(id As %Integer) As %Status [ PublicList = (result) ]
  {
      Set sc = $$$OK
      // ...
      Return sc
  }
  ```

- Reference instance members with the dot-dot prefix: `..Property`, `..Method()`.
  Call class methods with `##class(Package.Class).Method()` and the current
  class with `..#Parameter` (parameters) / `$classname()`.
- `$$$` = macro, `$` = system function or special variable, `^` = global,
  `%` = system/percent (a `%`-variable survives `New`; a `%`-named class/method
  belongs to a system or library package).
- Test for existence/definition with `$Data`, `$Get` (with default), `$IsObject`,
  `$ListValid` — never assume a variable or global node is defined.
- Prefer `$ListBuild`/`$List` lists and multidimensional arrays over delimited
  strings when structure matters; use `$Piece`/`$Length(...,delim)` for delimited.

### 4. Objects, SQL, and globals are one model

A persistent class is simultaneously an object (`%OpenId`, `%Save`), a SQL table,
and a global. Keep them consistent:

- Object API: `%New()`, `%Save()`, `%OpenId(id)`, `%ExistsId(id)`, `%DeleteId(id)`,
  `%Id()`. These return/expect a `%Status` where applicable.
- SQL: every persistent class projects to a table (`Schema.Table`). Use Dynamic
  SQL (`%SQL.Statement`) or Embedded SQL (`&sql(...)`) — never build SQL by string
  concatenation of user input (injection). See `references/persistence-and-sql.md`.
- Don't read/write a class's storage globals directly unless you defined that
  storage yourself. Use the object or SQL layer.

### 5. Mixing Embedded Python

- A method runs Python when it carries `[ Language = python ]`; the body is then
  Python and may `import iris` to reach the platform.
- From ObjectScript, call Python libraries via `##class(%SYS.Python).Import("name")`.
- Keep one method = one language. Don't interleave. See `references/embedded-python.md`.

### 6. Interoperability productions

- Build hosts from the standard bases: services extend `Ens.BusinessService`,
  operations `Ens.BusinessOperation`, processes `Ens.BusinessProcess(BPL)`.
- Pass data as message classes (`Ens.Request`/`Ens.Response`/`Ens.MessageBody`),
  not loose arguments. Transform with DTL (`Ens.DataTransformDTL`).
- Use `EnsLib.*` adapters for I/O; for HL7 use `EnsLib.HL7.*`, for FHIR the
  `HS.FHIRServer.*` stack. See `references/interoperability.md`.
- For healthcare standards (IHE profiles, CDA, FHIR conversion), route everything
  through **SDA** (`HS.SDA3.Container`) as the hub and reuse the shipped
  XSLT/DTL transforms and `HS.*` IHE components — don't hand-roll mappings. See
  `references/ihe-and-clinical-interop.md`.

### 7. Legacy M, raw globals, and debugging

- ObjectScript is a superset of standard M (MUMPS). Read legacy routines fluently;
  write **new** code in modern ObjectScript. Don't introduce naked references,
  indirection, or `Xecute`.
- Read a persistent class's generated storage globals (`^Pkg.ClassD/I/S`) only to
  **diagnose** — slot 1 of the data `$List` is `%%CLASSNAME`, then properties in
  `<Data>` order. Never `Set` them directly; write through object/SQL.
- To find a runtime bug: read the `$ZError` location (`label+off^Pkg.Class.1`),
  open the generated `.int` (compile with `k`), map back to the `.cls` method;
  check the application error log (`^ERRORS`); set breakpoints with `ZBREAK` or the
  IDE debugger. See `references/mumps-globals-and-debugging.md`.

---

## Workflow for a coding task

1. **Clarify the boundary.** What namespace/package? New class vs. editing an
   existing one? Persistent, serial, registered, or a routine? Which IRIS edition?
2. **Pick the model.** Object access, SQL, or direct global? Library default is the
   object/SQL layer.
3. **Read the relevant reference file(s)** from the table above. Reuse an asset:
   start from `assets/templates/` or adapt `assets/example-app/` rather than
   writing boilerplate.
4. **Write idiomatic UDL/ObjectScript** following the house rules. Include class
   reference doc comments (`///`) on every public member.
5. **Handle every `%Status` / exception** explicitly.
6. **Lint, then compile and test — don't just eyeball it.**
   - Structural check: `python3 scripts/lint_udl.py <your .cls files>` (must be 0 errors).
   - Real compile + tests: drop the classes into a source tree and run
     `assets/docker/run.sh`, which boots IRIS for Health, compiles, and runs the
     tests; a non-zero exit means it does not actually work. For a brand-new
     project, scaffold it with `scripts/new_project.sh <dir> <RootPackage>`.
   - Inside an existing instance you can also compile with
     `Do $System.OBJ.Compile("MyApp.Data.Patient","ck")` and run
     `Do ##class(%UnitTest.Manager).RunTest(...)` (see `references/persistence-and-sql.md`).
7. **Verify** against the official docs for anything version-specific.

> "Really programs" means the code compiles and the tests pass — prove it with
> the harness, don't assert it. When you can't run IRIS, at minimum lint every
> class and state clearly that runtime verification is pending.

## Self-check before returning code

- [ ] Class skeleton is valid UDL; `Extends` order is intentional.
- [ ] Every library call's `%Status`/exception is checked or propagated.
- [ ] Commands in PascalCase; procedure blocks with `{ }`; no stray dot-syntax.
- [ ] Names follow `references/naming-and-style.md` (packages, `%`-prefix, indices).
- [ ] No hand-written `Storage` unless intentional; no direct storage-global access.
- [ ] SQL is parameterized; object and SQL views of the data stay consistent.
- [ ] Public members have `///` doc comments.
- [ ] One language per method; Python methods marked `[ Language = python ]`.
- [ ] `scripts/lint_udl.py` reports 0 errors on the generated classes.
- [ ] Compiled and tested via `assets/docker/run.sh` (or runtime verification is
      explicitly flagged as pending).

> Source of truth: InterSystems IRIS for Health 2026.1 documentation at
> `https://docs.intersystems.com/irisforhealthlatest/`. `references/doc-map.md`
> lists the exact page for each topic.
