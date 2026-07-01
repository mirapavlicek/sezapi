# Naming, Formatting & Source Layout

The conventions that make IRIS code look native and stay maintainable. Apply
these consistently across every file.

Official docs: *Orientation for Server-Side Programming* (`GORIENT_intro`),
*Using ObjectScript → Syntax Basics* (`GCOS_syntax`). See `doc-map.md`.

## 1. Naming conventions

### Packages and classes
- Classes are namespaced with dot-separated **packages**:
  `Company.Application.Layer.ClassName`, e.g. `Acme.HIS.Data.Patient`.
- Package and class names use **PascalCase**. Mirror the package path in the file
  system: `Acme.HIS.Data.Patient` → `Acme/HIS/Data/Patient.cls`.
- Group by layer/domain (`.Data`, `.Msg`, `.API`, `.DT`, `.Tests`, `.Util`).
- **Never** create classes in a package starting with `%` — that prefix is
  reserved for InterSystems system/library classes (which live in the `%SYS`-ish
  shared space and are visible from every namespace).
- Avoid names colliding with system packages (`Ens`, `EnsLib`, `HS`, `%*`).

### Members
- **Properties, Methods, ClassMethods, Relationships, Queries**: PascalCase
  (`BirthDate`, `ComputeAge`, `OnProcessInput`).
- **Parameters**: UPPERCASE (`MAXLEN`, `ADAPTER`, `DOMAIN`).
- **Indices**: PascalCase, often suffixed `Index`/`Idx`/`Key`
  (`MRNIndex`, `NameIdx`, `PatientIDKey`).
- **Private/internal helpers**: PascalCase + `[ Private ]` / `[ Internal ]`.

### Variables, labels, globals
- **Local variables**: short and lowercase/camelCase (`sc`, `id`, `patient`,
  `resultSet`). `sc` is the idiomatic name for a `%Status`.
- **`%`-locals** (`%var`) survive argumentless `New` — use for utility/scratch only.
- **Globals**: `^Package.Name` matching the owning class/app
  (`^Acme.HIS.PatientD`). Let the compiler name storage globals; name *application*
  globals deliberately and document them.
- **Labels/tags** in routines: PascalCase or lowercase, no spaces.
- **Macros**: UPPERCASE with the `$$$` reference prefix (`$$$MYAPPDEFAULT`).

## 2. Formatting

- **Commands and functions in PascalCase** in source files (`Set`, `Write`,
  `$Length`, `$ListBuild`). Full words, not abbreviations — abbreviations (`s`,
  `w`, `d`) are only for interactive terminal use.
- **Indent with 4 spaces** (the IDE default). Indent inside `{ }` blocks.
- One statement idea per line; avoid stacking many commands on one line. A
  postconditional (`Set:cond x=1`, `Quit:done`) is fine and idiomatic.
- Put the opening brace of a class/member on its **own line** (UDL style):

  ```objectscript
  Method Foo() As %Status
  {
      Return $$$OK
  }
  ```

- Inside method bodies, `{` for `If`/`For`/`While`/`Try` may sit at end of line:
  `If x>0 {` … `}`.
- Space after commas in argument lists; parenthesize mixed-operator expressions
  (ObjectScript has **no operator precedence** — strictly left to right).
- Keep lines reasonably short; use `##continue` only when necessary.

## 3. Documentation

- Use `///` comments on the **class** and **every public member** — they generate
  the Class Reference (the IRIS "Javadoc"). HTML and `{Package.Class}` /
  `{Package.Class.Member}` cross-links are supported.

  ```objectscript
  /// Computes the patient's age in whole years as of <var>asOf</var>.
  /// Returns 0 when <property>BirthDate</property> is empty.
  ClassMethod ComputeAge(birth As %Date, asOf As %Date = {+$Horolog}) As %Integer
  ```

- Use `//` for ordinary inline implementation comments. Reserve `;` style for
  legacy routines.
- Document non-obvious globals, locks, and macros where they're defined.
- Prefer self-explaining names over comments that restate the code.

## 4. Source layout & lifecycle

- One class per `.cls`; routines in `.mac` (compiled to `.int`); includes in
  `.inc`; the package path mirrors the dotted name.
- Keep code under **source control** (Git) by exporting UDL — use the VS Code
  *InterSystems ObjectScript* extension or Studio with the Server-Side Source
  Control / `isfs` workflow. Store `.cls/.mac/.inc` text, not the database.
- Use the **IPM / Package Manager (`zpm`)** for distributable modules
  (`module.xml` manifests) when shipping reusable code.
- Compile with flags: `Do $System.OBJ.Compile("Pkg.Cls","ck")`
  (`c`=compile dependents, `k`=keep generated source) or
  `Do $System.OBJ.CompilePackage("Pkg")`. The IDE compiles on save.
- Run `%UnitTest` suites in CI; keep test classes in a `.Tests` package and clean
  up their data.

## 5. Things to avoid in new code

- Argumentless `Do` dot-syntax blocks and `Goto`-driven flow — use `{ }` blocks
  and procedures.
- Single-letter command abbreviations in committed source.
- `$ZTrap`/`$ZError` error handlers — use `Try/Catch` + `%Status`.
- Silently ignoring a returned `%Status`.
- Hand-written `Storage` on ordinary persistent classes.
- Direct reads/writes of a class's storage globals — go through object or SQL.
- Building SQL by concatenating user input — parameterize with `?`/`:host`.
- Defining classes in a `%`-package or names clashing with system packages.
