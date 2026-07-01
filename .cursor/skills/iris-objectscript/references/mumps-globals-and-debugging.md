# MUMPS / Standard M, Globals & Debugging Compiled Code

Three lower-level skills: writing and maintaining **standard M (MUMPS)** and legacy
routines, working directly with **globals** — including the auto-generated storage
globals behind persistent classes — and **finding bugs in compiled (`.int`)
code** with traps, the error log, and the debugger.

Official docs (see `doc-map.md`): *Using ObjectScript* — Open M Language
Compatibility (`GCOS_mcompat`), Command-Line Routine Debugging (`GCOS_debug`),
Legacy `^%ETN` Error Logging (`GCOS_etn`); *ObjectScript Reference* — `ZBREAK`
(`RCOS_czbreak`), `$ZERROR` (`RCOS_vzerror`); *Using Globals* (`GGBL_USING`),
Storage Globals (`GOBJ_storageglobals`).

## Contents
1. ObjectScript vs standard M (MUMPS)
2. Writing & maintaining M routines
3. Globals: the storage layer
4. The generated storage globals of a persistent class
5. The class dictionary globals
6. Inspecting globals at runtime
7. Compiled code: `.mac` → `.int` → `.obj`
8. Finding bugs in compiled code (debugger, traps, error log)

---

## 1. ObjectScript vs standard M (MUMPS)

ObjectScript is a **superset of ISO 11756‑1999 standard M** (identical to the old
ANSI‑standard MUMPS). Existing M applications run on IRIS unchanged; you can mix
standard‑M routines with modern class code in the same namespace.

What ObjectScript adds over standard M: objects/OOP, procedure and control blocks
with `{ }`, relaxed whitespace rules, `Try/Catch`, and many extra functions
(`$ZxxX`, `$List*`, `$System.*`). It still supports ISO‑11756 standard error
behavior. So everything in `references/objectscript-language.md` is available to M
code; this section covers the **older idioms** you will meet in legacy code.

## 2. Writing & maintaining M routines

Standard‑M / legacy routine style (terse, line‑oriented). It is valid and runs,
but for **new** code prefer modern ObjectScript (PascalCase commands, procedures,
`Try/Catch`). You need fluency in the old style to read and fix legacy routines.

```objectscript
MYROUT ; description ; author/date
 ; ---- standard-M conventions ----
 ; * one space before the first command on a line; commands separated by space
 ; * line labels in column 1; code indented by at least one space
 ; * single-letter command abbreviations are normal in M (S=Set, W=Write,...)
 ; * dot syntax for blocks; GOTO for flow; $ZTRAP for errors
 N I,X            ; NEW (scope) locals
 S X=0
 F I=1:1:10 D     ; argumentless DO + dot block
 . S X=X+I
 . W:I#2 I,!      ; postconditional write of odd numbers
 W "sum=",X,!
 Q                ; QUIT

TAG(A,B) ; an extrinsic function: $$TAG^MYROUT(1,2)
 Q A+B           ; QUIT with a value
```

Things to know when reading M:

- **Commands are case‑insensitive and often abbreviated**: `S`et, `W`rite,
  `D`o, `Q`uit, `N`ew, `K`ill, `I`f, `E`lse, `F`or, `H`alt/`H`ang, `G`oto,
  `M`erge, `R`ead, `X`ecute. In source you maintain, expand them to PascalCase
  when you touch the code.
- **Naked reference** `^(subscript)` reuses the last global reference's leading
  subscripts: after `S X=^A(1,2,3)`, `S Y=^(4)` means `^A(1,2,4)`. Powerful and
  bug‑prone — make it explicit when refactoring.
- **Indirection** `@`: `S @name=1` (name indirection), `S X=@expr@(sub)` — runtime
  evaluation of names/subscripts; `X`ecute runs a string as code. Treat as a smell
  in new code.
- **`$ZTRAP` / `$ETRAP`** error handlers and `GOTO` are the legacy control/error
  mechanisms (see §8).
- Whitespace is significant in M: exactly one space between the line‑start and the
  first command; arguments have no spaces around commas in strict M.
- Routines live in `.mac` (with macros/`#define`) or `.int` (intermediate). Call
  with `Do ^ROUT`, `Do LABEL^ROUT`, value with `$$LABEL^ROUT(args)`.

## 3. Globals: the storage layer

A **global** is a persistent, sparse, ordered, multidimensional tree on disk —
the substrate under objects, SQL tables, and hand‑written storage. Syntax is the
same as a local array but with a `^` prefix.

```objectscript
Set ^Acme.Config("smtp","host") = "mail.example.com"
Set ^Acme.Config("smtp","port") = 25
Write ^Acme.Config("smtp","host")           // read
Kill ^Acme.Config("smtp")                    // delete a subtree
```

- Subscripts collate numeric‑then‑string; traverse with `$Order` (one level) and
  `$Query` (whole subtree, depth‑first). `$Increment(^g)` is the atomic counter.
- Globals can be mapped to specific databases (global mapping) and made temporary
  (`^IRIS.Temp*`, `^||ppg` process‑private). See `references/objectscript-language.md` §7.

## 4. The generated storage globals of a persistent class

When you compile a `%Persistent` class, IRIS generates a `Storage Default` map
and stores data in globals named after the class:

| Global | Holds |
|---|---|
| `^Pkg.ClassD` | **D**ata: top node = the ID counter; node per row, subscripted by ID |
| `^Pkg.ClassI` | **I**ndex data (one subtree per index) |
| `^Pkg.ClassS` | **S**tream data |

Each row node packs all non‑transient properties into one `$ListBuild`:

```
^MyApp.PersonD       = 2                          ; ID counter ($Increment)
^MyApp.PersonD(1)    = $LB("",530,"Abraham")      ; row 1
^MyApp.PersonD(2)    = $LB("",680,"Philip")       ; row 2
```

Reading this is essential for debugging persisted data:

- The **first `$List` element is the `%%CLASSNAME` slot** (empty `""` for the base
  class; set for subclasses in the same extent). Property values follow in
  storage order — check the class's `Storage` definition (`<Data>` list) for the
  exact slot → property mapping.
- The ID is assigned by `$Increment` for objects, or `$Sequence` for tables
  created via SQL DDL.
- Storage keywords come from `DEFAULTGLOBAL`: `COUNTERLOCATION`, `DATALOCATION`,
  `IDLOCATION`, `INDEXLOCATION`, `STREAMLOCATION`.

```objectscript
// pull a property out of a raw data node (slot 3 here):
Set name = $ListGet(^MyApp.PersonD(id), 3)
```

**Rule:** read these globals to *diagnose*, but write through the object/SQL layer
so indexes and validation stay consistent. Direct `Set ^...D(...)` bypasses
indices and callbacks and will corrupt the extent. If you must (data fix), update
the indices too (`%BuildIndices`) and verify with `$System.OBJ`.

Docs: Storage Globals (`GOBJ_storageglobals`), SQL/Class use of multidimensional
storage (`GGBL_sqlobj`), Storage Definitions (`GOBJ_storage`).

## 5. The class dictionary globals

Class/routine metadata also lives in globals (handy to know when something seems
"stuck" after a bad compile):

- `^oddDEF` — class **definitions** (source dictionary).
- `^oddCOM` — **compiled** class descriptors. `^oddEXT`, `^oddMAP` — runtime maps.
- `^rINC`, `^rMAC`, `^rOBJ`, `^ROUTINE` — routine source/object code.

You normally never touch these — use `$System.OBJ.Compile`, the IDE, or
`$System.OBJ.Delete`. But seeing them in a `$Query` or error explains where code
and metadata are kept.

## 6. Inspecting globals at runtime

```objectscript
ZWrite ^MyApp.PersonD          // dump a global subtree (also: zw ^MyApp.PersonD)
ZWrite person                  // dump an OREF / local and its subnodes
Write $Data(^MyApp.PersonD(99)) // 0/1/10/11 — does the node/subtree exist?
Set k="" For  Set k=$Order(^MyApp.PersonD(k)) Quit:k=""  Write k,": ",^MyApp.PersonD(k),!
```

- `ZWrite`/`zw` is the fastest way to see exactly what is stored.
- In the Management Portal: System Explorer → Globals to browse/edit (carefully).
- `Do ##class(%GlobalEdit)...` and `^%G`, `^%GD` utilities view/dump globals.

## 7. Compiled code: `.mac` → `.int` → `.obj`

Understanding the pipeline is the key to debugging "precompiled" code:

```
   .cls / .mac  ──compile──▶  .int (intermediate ObjectScript)  ──▶  .obj (object code)
```

- A **class** compiles into one or more generated routines named like
  `Pkg.Class.1.int` (methods become labels/procedures inside). Property methods,
  `%OnBeforeSave`, SQL, etc. all become real code there.
- A **`.mac`** routine (with macros) compiles to a **`.int`** routine (macros
  expanded), then to `.obj`. The `.int` is what actually runs and what the
  debugger and error locations refer to.
- Keep the generated intermediate code by compiling with the **`k`** flag
  (`Do $System.OBJ.Compile("MyApp.Person","ck")`); then you can read it.
- **View the generated `.int`** for a class in VS Code / Studio via *View Other
  Code* (or open `Pkg.Class.1.int`), or print it:

```objectscript
Do ListRoutines^%RD          // list routines
ZPrint ^MyApp.Person.1       // print a generated routine's source
```

An error reported as `<UNDEFINED>zMethod+4^MyApp.Person.1` points at **line 4 of
label `zMethod` in the generated routine `MyApp.Person.1`** — open that `.int` to
see the actual failing line, then map it back to the method in the `.cls`.

## 8. Finding bugs in compiled code

### Read the error location

`$ZERROR` holds the last error name **and location** (`label+offset^routine`).
After a failure:

```objectscript
Write $ZError          // e.g. <UNDEFINED>zProcess+7^MyApp.Job.1 *patient
Write $ECODE           // ISO error code list, e.g. ,M6, (UNDEFINED)
Do $System.Status.DisplayError(sc)   // for a %Status
```

`$STACK` / `$STACK(-1,...)` and `Do ^%STACK` show the execution stack at the
error — invaluable for "how did we get here".

### The application error log (`^ERRORS`)

Unhandled errors (and explicit `LOG^%ETN` calls) are recorded in the application
error log, global `^ERRORS`:

```objectscript
Do LOG^%ETN          // log the current error (set $ZError first for the message)
Do ^%ERN             // browse the error log interactively (%ERN utility)
ZWrite ^ERRORS       // raw dump of logged errors
```

Or view it in the Management Portal: **System Operation → System Logs →
Application Error Log**. Each entry saves the error, the stack, and variable
values at the time — the first place to look for an intermittent production bug.

### The command‑line debugger (`ZBREAK`)

```objectscript
// break when execution reaches label zProcess+0 in the generated routine:
ZBreak zProcess+0^MyApp.Job.1
// watchpoint: break when local 'patient' is Set or Killed:
ZBreak *patient
// break with a condition and an action (label+off^rou:action:condition:code):
ZBreak zProcess+2^MyApp.Job.1:"B":"id=42":"Write !,""hit id 42"""
ZBreak /OFF            // clear all breakpoints
```

- A breakpoint suspends execution at a line; up to 20 routines, 20 breakpoints each.
- A **watchpoint** (`*var`) breaks when that variable changes (not for system vars).
- At a break you are in the debug prompt: `ZWrite` to inspect, `Set` to patch,
  `Goto` to resume; `BREAK "S"` enables single‑step, `/STEP` / `/NOSTEP` control
  stepping into generated modules.
- `BREAK` (no args) toggles whether Ctrl‑C interrupts into the debugger.
- For class code, debug the **generated `.int`** (compile with `k`); the IDE
  debuggers (VS Code ObjectScript, Studio — `GSTUDIO_Debugger`) let you set
  breakpoints in the `.cls` and map them to the generated code automatically.

### Legacy traps (you will see these in old code)

```objectscript
 Set $ZTrap="ERR"      ; on error, GOTO ERR in this routine
 ; ... code ...
 Quit
ERR  Write "caught: ",$ZError,!  Do LOG^%ETN  Set $ZTrap=""  Quit
```

`$ZTrap`/`$ETrap` are the pre‑`Try/Catch` mechanism. Keep them when maintaining M
routines, but use `Try/Catch` (`references/objectscript-language.md` §9) for new
code — it unwinds cleanly and interoperates with `%Status`.

---

### MUMPS / globals / debugging checklist

- [ ] New code in modern ObjectScript; legacy M read fluently and expanded when edited.
- [ ] No new naked references / indirection / `Xecute`; documented when kept.
- [ ] Generated storage globals (`^ClassD/I/S`) read only to diagnose; writes go
      through object/SQL (slot 1 = `%%CLASSNAME`, then properties in `<Data>` order).
- [ ] Errors traced via `$ZError` location → open the generated `.int` (compiled
      with `k`) → map back to the `.cls` method.
- [ ] Checked the application error log (`^ERRORS` / Management Portal) for the stack.
- [ ] Debugged with `ZBREAK`/watchpoints or the IDE debugger; legacy `$ZTrap`
      preserved in M, `Try/Catch` used in new code.
