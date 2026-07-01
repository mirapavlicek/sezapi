# ObjectScript Language Reference

The server-side language of InterSystems IRIS. Case-insensitive keywords,
sparse multidimensional data, late binding. This file covers syntax, variables,
operators, commands, functions, special variables, macros, flow control, error
handling, and I/O.

Official docs: *Using ObjectScript* (`GCOS_intro`) and *ObjectScript Reference*
(`RCOS_intro`). See `doc-map.md` for direct links.

## Contents
1. Syntax basics
2. Data, variables, and scope
3. Operators
4. Commands (most-used)
5. System functions ($-functions)
6. Special variables ($-variables)
7. Multidimensional arrays and lists
8. Flow control & procedures
9. Error handling
10. Macros and include files
11. I/O and devices

---

## 1. Syntax basics

- A line is `label  command arg,arg  command arg`. Commands are separated by a
  space; arguments by commas. **One space** between a command and its first
  argument; the postconditional and arguments follow with no extra spaces.
- Keywords are case-insensitive. **Write commands and functions in PascalCase**
  in source (`Set`, `Write`, `$Length`); abbreviations (`s`, `w`) are for the
  terminal only.
- Identifiers (variables, labels) **are case-sensitive**: `Count` ≠ `count`.
- Comments: `//` (rest of line), `;` (rest of line, classic), `#;` (whole line,
  not compiled), and `/* … */` (block). Use `///` for class **documentation**
  comments that appear in the Class Reference.
- String literals use double quotes; embed a quote by doubling it: `"say ""hi"""`.
- Numbers are decimal; `$Double` for IEEE floats; leading/trailing zeros are
  canonicalized (`Write +"007.50"` → `7.5`).
- Postconditional: append `:condition` to a command to run it conditionally —
  `Do:x>0 ^Routine`, `Quit:done`.

## 2. Data, variables, and scope

ObjectScript has **one datatype: string**. Numbers, booleans, dates, and `$List`
structures are all strings interpreted by context. Truth = non-zero numeric.

Variable kinds:

- **Local** — `Set x = 1`. Process-private, in memory. Scoped by `New`/procedure.
- **Process-private global** — `Set ^||temp = 1` (or `^|"^"|`). In memory, private
  to the process, survives across routines; ideal for scratch data.
- **Global** — `Set ^Data("x") = 1`. Persistent, on disk, shared. Prefix `^`.
- **Special/`%` variables** — `%`-named locals (e.g. `%sc`) are **not** cleared by
  an argumentless `New`; useful for utility code.
- **Object reference (OREF)** — `Set p = ##class(My.Class).%New()`. `$IsObject(p)`
  is true. Stored in a local variable; lives while referenced.

Existence and safe access — never assume defined:

```objectscript
If $Data(x) { … }                 // 0 undef, 1 defined, 10 has subnodes, 11 both
Set name = $Get(person("name"), "Unknown")   // default if undefined
Set:'$Data(count) count = 0
```

Scoping with procedures (preferred) or `New`:

```objectscript
Method Demo() [ PublicList = (shared) ]
{
    // Variables set here are private to this method unless in PublicList.
}
```

Avoid leaking variables: in routines use `New var1,var2` at the top of a section,
or — better — write **procedures** (label`(args) [vars] { … }`) which auto-scope.

## 3. Operators

- Arithmetic: `+ - * / \` (integer divide) `#` (modulo) `**` (power).
- String: `_` (concatenate).
- Comparison: `=` `'=` `<` `>` `<=` `>=`. `[` (contains), `]` (follows),
  `]]` (sorts-after), `?` (pattern match, e.g. `x?1.N` = one-or-more numerics).
- Logical: `&` / `&&` (and), `!` / `||` (or), `'` (not). `&&`/`||` short-circuit.
- Precedence in ObjectScript is **strictly left-to-right** with no operator
  precedence — use parentheses: `Set x = 2 + 3 * 4` yields 20, not 14. Always
  parenthesize mixed expressions.

## 4. Commands (most-used)

| Command | Purpose |
|---|---|
| `Set` | Assign: `Set x = expr`, `Set ^g(k) = v`, `Set obj.Prop = v` |
| `Do` | Call a routine/method/procedure: `Do ^Tag`, `Do obj.Method()` |
| `Return` | Exit current method/procedure, optionally with a value (preferred over `Quit` for returning) |
| `Quit` | Exit a block/loop/routine; `Quit value` returns from an extrinsic |
| `If`/`ElseIf`/`Else` | Block conditionals with `{ }` |
| `For` | `For i=1:1:10 { … }`, `For { … Quit:done }`, `For i=1,3,5 { … }` |
| `While`/`Do…While` | Pre/post-tested loops |
| `Write` / `Write !` | Output to current device (`!`=newline, `?n`=column) |
| `Read` | Input from current device |
| `Kill` | Delete a variable/global/subtree: `Kill x`, `Kill ^g(k)` |
| `New` | Create a fresh scope for named locals |
| `Merge` | Copy an array subtree: `Merge ^g = local` |
| `$Order`/`$Query` loops | Iterate sparse arrays (see §7) |
| `Throw` | Raise an exception object |
| `Try`/`Catch` | Structured exception handling |
| `TStart`/`TCommit`/`TRollback` | Transactions (see persistence-and-sql.md) |
| `Lock` | Concurrency locks: `Lock +^g(id)`, `Lock -^g(id)` |
| `Job` | Start an asynchronous background process |

`Set` supports multiple targets and `$Piece`/`$List`/`$Extract` on the left:
`Set $Piece(csv,",",2) = "new"`, `Set $List(lb,3) = val`, `Set x=1,y=2`.

## 5. System functions ($-functions)

String & value:

- `$Length(s)` / `$Length(s,delim)` — length, or piece count.
- `$Extract(s,from,to)` — substring by position.
- `$Piece(s,delim,n)` / `$Piece(s,delim,from,to)` — delimited substring.
- `$Find`, `$Translate`, `$Replace`, `$Reverse`, `$ZStrip`, `$ZConvert(s,"U"/"L"/"W"/"T")`.
- `$Justify(s,width[,dec])`, `$Number(s,fmt)`, `$FNumber(n,fmt,dec)`.
- `$Char(n…)` / `$ASCII(s,n)` — code points.
- `$Case(x, v1:r1, v2:r2, : default)` — value switch returning a result.
- `$Select(c1:r1, c2:r2, 1:default)` — first true branch (must always match one).

`$List` family (packed lists — compact, ordered, type-preserving):

- `$ListBuild(a,b,c)`, `$List(lb,n)`, `$ListGet(lb,n,default)`, `$ListLength(lb)`,
  `$ListNext(lb,ptr,val)`, `$ListFind`, `$ListSame`, `$ListToString`/`$ListFromString`.

Existence, type, and arrays:

- `$Data(x)`, `$Get(x,default)`, `$Order(^g(k),dir)`, `$Query(^g(k))`,
  `$Increment(^g)` (atomic counter), `$IsObject(x)`, `$ListValid(x)`.

Date/time (the `$Horolog` format is `days,seconds`):

- `$Horolog` (now), `$ZDate(h,fmt)`, `$ZDateH(str,fmt)`, `$ZTime`, `$ZTimeH`,
  `$Now()`, `$ZDateTime`/`$ZDateTimeH`. For SQL-style use `$System.SQL.Functions`.

Class/object utility:

- `$ClassName(obj)`, `$ClassMethod(class,method,args…)`, `$Method(obj,name,args…)`,
  `$Property(obj,name)`, `$Parameter(class,name)`.

## 6. Special variables ($-variables)

| Variable | Meaning |
|---|---|
| `$Horolog` | Current date,time as `ddddd,sssss` |
| `$Job` | Current process ID |
| `$Username` / `$Roles` | Security context |
| `$Namespace` | Current namespace (use `New $Namespace` then `Set $Namespace="X"` to switch and auto-restore) |
| `$This` | The current object (OREF) inside an instance method |
| `$ZError` / `$ZTrap` | Legacy error state/handler — avoid in new code |
| `$Test` | Result of the last command with a timeout |
| `$STORAGE`, `$ZStorage` | Available memory |
| `$System` | Entry to the `%SYSTEM` utility package: `$System.OBJ`, `$System.SQL`, `$System.Status`, `$System.Encryption`, … |
| `$ECODE`, `$STACK`, `$ZVERSION` | Error code list, call stack depth, version string |

## 7. Multidimensional arrays and lists

Sparse, ordered-by-subscript trees — the heart of the language. Local
(`a(...)`), global (`^a(...)`), or object-array properties all share this model.

```objectscript
Set fruit("apple") = 1, fruit("banana") = 2, fruit("cherry") = 3

// Iterate in collating order with $Order:
Set key = ""
For {
    Set key = $Order(fruit(key))
    Quit:key=""
    Write key, " = ", fruit(key), !
}

// $Order with the data retrieved in one call (3rd arg gets the value):
Set key = "" For { Set key = $Order(fruit(key),1,val) Quit:key=""  Write key,"=",val,! }
```

- Subscripts collate in **numeric-then-string** order; control with collation
  functions when needed.
- `$Order(node, -1)` iterates in reverse. `$Query` walks the entire subtree
  depth-first (multi-level). `$Increment(^counter)` gives race-free counters.
- Choose `$ListBuild` lists for fixed records, multidimensional arrays for
  keyed/sparse data, `$Piece` strings only for simple delimited text.

## 8. Flow control & procedures

Modern style uses braces and procedures; avoid line-labels + `Goto` + dot-syntax.

```objectscript
ClassMethod Categorize(score As %Integer) As %String
{
    Return $Case(score \ 10,
        10: "A", 9: "A",
        8: "B",
        7: "C",
        : "F")
}

ClassMethod SumPositive(list As %List) As %Integer
{
    Set total = 0, ptr = 0
    While $ListNext(list, ptr, val) {
        Continue:'$IsValidNum(val)
        Set:val>0 total = total + val
    }
    Return total
}
```

- `If/ElseIf/Else`, `For { }`, `While { }`, `Do { } While cond`, with
  `Continue` and `Quit`/`Return`.
- Argumentless `Do { … }` creates an inline block (useful for a scoped `Quit`).
- A **routine** (`.mac`) holds labelled subroutines; call extrinsic functions with
  `$$tag^routine(args)` returning a value via `Quit value`.

## 9. Error handling

**Two coexisting systems — use exceptions + `%Status` in new code.**

### `%Status` values (the library contract)

```objectscript
Set sc = obj.%Save()
If $$$ISERR(sc) Quit sc                     // propagate
Do $System.Status.DisplayError(sc)          // human-readable, for debugging
Set text = $System.Status.GetErrorText(sc)  // message string
```

Macros (from `%occStatus.inc`, included automatically in class methods):

- `$$$OK` — success status.
- `$$$ERROR(code, args…)` — build an error, e.g.
  `$$$ERROR($$$GeneralError, "Patient not found: "_id)`.
- `$$$ISOK(sc)` / `$$$ISERR(sc)` — test.
- `$$$ADDSC(sc1, sc2)` — accumulate multiple errors into one status.

### Exceptions (Try/Catch — modern, preferred for control flow)

```objectscript
Method Load(id As %String) As %Status
{
    Set sc = $$$OK
    Try {
        Set obj = ##class(My.Class).%OpenId(id, , .sc)
        $$$ThrowOnError(sc)              // turn a bad %Status into an exception
        If '$IsObject(obj) {
            Throw ##class(%Exception.General).%New("NotFound", 5001, , "id="_id)
        }
        // … work …
    }
    Catch ex {
        Set sc = ex.AsStatus()           // convert exception back to %Status
        // Optionally: Do ex.Log()  /  $$$LOGERROR(ex.DisplayString())
    }
    Return sc
}
```

- `ex` is an `%Exception.AbstractException` (`%Exception.General`,
  `%Exception.SystemException`, `%Exception.StatusException`, …).
  Members: `.Name`, `.Code`, `.Data`, `.Location`, `.AsStatus()`, `.DisplayString()`.
- `$$$ThrowOnError(sc)` raises an exception only when `sc` is an error;
  `$$$ThrowStatus(sc)` always throws the given status. Both are standalone
  statements (no `Set`). `$$$ThrowOnError(sc)` is the common, readable form.
- **Do not** use `$ZTrap`/`$ZError`/`Goto` error handlers in new code — they are
  legacy and don't unwind cleanly through `Try` frames.

### Rules

- Never swallow a status: check `$$$ISERR` and either handle or `Return sc`.
- Don't `Write` errors from library code; return/throw them and let the caller
  decide on presentation/logging.
- In interoperability code, return `%Status` from `On*` methods so the framework
  can retry/suspend messages (see `interoperability.md`).

## 10. Macros and include files

- Macros expand at **compile time**; defined in `.inc` include files with
  `#define NAME value` / `#define NAME(args) expansion`.
- Reference a macro with the `$$$` prefix: `$$$MyMacro`, `$$$MyMacro(arg)`.
- Include macros in a class with the `Include` directive **before** `Class`:

  ```objectscript
  Include (%occStatus, MyApp.Macros)

  Class MyApp.Foo Extends %RegisteredObject { … }
  ```

- In a routine, use `#Include MyApp.Macros`.
- Common system includes: `%occStatus` (status macros), `%occInclude` (broad set),
  `%systemInclude`, `Ensemble`/`EnsConstants` (interop logging macros like
  `$$$LOGINFO`, `$$$LOGWARNING`, `$$$LOGERROR`).
- Preprocessor directives: `#define`, `#def1arg`, `#dim` (declare a variable's
  type for the IDE: `#dim patient As MyApp.Data.Patient`), `#if/#elseif/#endif`,
  `##continue` (line continuation), `##; ` (compile-time comment).
- `$$$` macros are also how the framework exposes constants — e.g.
  `$$$GeneralError`, `$$$CurrentClass`, `$$$cCLASSname`.

`#dim` is strongly recommended on object variables — it gives the IDE type info
and self-documents the code:

```objectscript
#dim rs As %SQL.StatementResult
#dim patient As MyApp.Data.Patient
```

## 11. I/O and devices

- The **current device** is the implicit target of `Write`/`Read`. `$IO` holds it.
- Open/use/close other devices: `Open dev:params:timeout`, `Use dev`, `Close dev`.
- Files: prefer the stream classes (`%Stream.FileCharacter`,
  `%Stream.FileBinary`) and `%Stream.GlobalCharacter` over raw device I/O for
  robustness and Unicode handling.
- For formatted terminal output use `Write !` (newline) and `Write ?col`
  (tab to column). For application output prefer returning data, not writing.

---

### Idiom quick-reference

```objectscript
Set name = $Get(person("name"), "")              // safe read with default
Set count = $Increment(^App.Counter)             // atomic sequence
Set sc = $$$OK                                     // start a status accumulator
Set obj = ##class(Pkg.Cls).%New()                 // new instance
$$$ThrowOnError(obj.%Save())                       // save, or throw on bad %Status
Set ok = (str ? 1.E1"@"1.E1"."2.3A)                // pattern match an email-ish string
```
