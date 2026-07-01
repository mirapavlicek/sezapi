# Documentation Map — Authoritative Sources

When a fact is version- or API-specific, or you need detail beyond this skill,
consult the official InterSystems IRIS for Health 2026.1 documentation. This map
gives you the exact page for each topic.

**Base URL pattern** (append a `KEY`):
`https://docs.intersystems.com/irisforhealthlatest/csp/docbook/DocBook.UI.Page.cls?KEY=<KEY>`

- Full catalog: `?KEY=ALL`
- Class Reference (library class/method signatures): `?KEY=ACLASSREF`
- The doc site is JavaScript-rendered; open links in a browser, or use the site
  search at `https://docs.intersystems.com/` for specific functions/commands.
- Links below were taken from the live 2026.1 navigation. KEYs marked **(verify)**
  are book-level entry points whose exact sub-page key may shift between releases —
  open the book and navigate, or search by title.

---

## Orientation & language

| Topic | KEY |
|---|---|
| Orientation for server-side programming (intro) | `GORIENT_intro` |
| Programming tutorials | `GORIENT_tutorials` |
| Class definitions overview | `GORIENT_class` |
| Objects & object API | `GORIENT_object` |
| Persistent objects & SQL (multi-model) | `GORIENT_persistence` |
| Namespaces & databases | `GORIENT_enviro` |
| Unicode support | `GORIENT_unicode` |
| ObjectScript landing | `PAGE_objectscript` |
| Using ObjectScript — Introduction | `GCOS_intro` |
| Using ObjectScript — Syntax Basics (naming, case, comments) | `GCOS_syntax` |
| Using ObjectScript — Procedure Syntax | `GCOS_procedures` |
| Using ObjectScript — Commands | `GCOS_commands` |
| ObjectScript Reference (commands/functions/special vars) | `RCOS` |
| Extending languages (custom $z commands) | `GSTU_customize_zlang` |

## Globals

| Topic | KEY |
|---|---|
| Globals — Introduction | `GGBL_intro` |
| Globals — Formal rules / structure | `GGBL_structure` |
| Global mapping & subscript-level mapping | `GGBL_mapping` |
| Globals with SQL & objects | `GGBL_sqlobj` |
| Temporary globals | `GGBL_tempgbl` |

## Classes (Defining & Using Classes — `GOBJ_*`)

| Topic | KEY |
|---|---|
| Class programming (intro) | `GOBJ_intro` |
| Defining classes | `GOBJ_classes` |
| Compiling classes | `GOBJ_classes_compile` |
| Class documentation (`///`) | `GOBJ_classdoc` |
| Packages | `GOBJ_packages` |
| Class parameters | `GOBJ_parameters` |
| Methods | `GOBJ_methods` |
| Registered objects (%RegisteredObject) | `GOBJ_objapi` |
| Properties | `GOBJ_properties` |
| Property methods | `GOBJ_propmethods` |
| Persistent objects (concepts) | `GOBJ_persobj_intro` |
| Working with persistent objects | `GOBJ_persobj` |
| Defining persistent classes | `GOBJ_defpersobj` |
| Object concurrency options | `GOBJ_concurrency` |
| Storage definitions | `GOBJ_storage` |
| Storage globals & naming | `GOBJ_storageglobals` |
| Literal properties | `GOBJ_proplit` |
| Common data type classes | `GOBJ_proplit_available_cls` |
| Common property parameters | `GOBJ_propparams` |
| Collections (list/array) | `GOBJ_propcoll` |
| Streams | `GOBJ_propstream` |
| Object-valued properties | `GOBJ_propobj` |
| Relationships | `GOBJ_relationships` |
| Other options for persistent classes (indices, FKs, triggers) | `GOBJ_persother` |
| Method & trigger generators | `GOBJ_generators` |
| Class queries | `GOBJ_queries` |
| XData blocks | `GOBJ_xdata` |
| Class projections | `GOBJ_projections` |
| Callback methods (%On*) | `GOBJ_callbacks` |
| Defining data type classes | `GOBJ_datatypes` |
| Dynamic dispatch | `GOBJ_dynamicdispatch` |
| ObjectScript features for classes | `GOBJ_specialcos` |

## Class Definition Reference (UDL keywords — `ROBJ_*`)

| Topic | KEY |
|---|---|
| Introduction | `ROBJ_classdef` |
| Top-level class syntax & keywords | `ROBJ_class` |
| Foreign keys | `ROBJ_foreignkey` |
| Indices | `ROBJ_index` |
| Methods | `ROBJ_method` |
| Parameters | `ROBJ_parameter` |
| Projections | `ROBJ_projection` |
| Properties | `ROBJ_property` |
| Queries | `ROBJ_query` |
| Triggers | `ROBJ_trigger` |
| XData | `ROBJ_xdata` |
| Storage | `ROBJ_storage` |

## Standard M (MUMPS), debugging, error log

| Topic | KEY |
|---|---|
| Open M Language Compatibility | `GCOS_mcompat` |
| Supported Languages | `ISP_languages` |
| Command-Line Routine Debugging | `GCOS_debug` |
| `ZBREAK` (set breakpoints/watchpoints) | `RCOS_czbreak` |
| `BREAK` | `RCOS_cbreak` |
| Routine & Debugging Commands (contents) | `RCOS_ZCOMMANDS` |
| `$ZERROR` special variable | `RCOS_vzerror` |
| Legacy: Traditional Error Processing (`$ZTrap`) | `GCOS_errors_trad` |
| Legacy: Using `^%ETN` for Error Logging | `GCOS_etn` |
| System Error Messages reference | `RERR_system` |
| Studio debugger | `GSTUDIO_Debugger` |
| Object storage tutorial | `TOS_OBJECTSTORAGE` |

## SQL

| Topic | KEY |
|---|---|
| Using InterSystems SQL — SQL Features | `GSQL_intro` |
| InterSystems SQL Reference (book) | `RSQL` |
| Globals/SQL/objects relationship | `GGBL_sqlobj` |

> For specific SQL functions, statements, and the optimizer, use the site search
> or open the SQL books from the `ALL` catalog. Embedded SQL host-variable syntax
> and `%SQL.Statement` Dynamic SQL are covered in `persistence-and-sql.md`.

## Transactions, locking, parallel processing

| Topic | KEY |
|---|---|
| Transaction processing | `GAPPS_tp` |
| Locking & concurrency control | `GAPPS_lockbasics` |
| Locking examples | `GAPPS_lockexamples` |
| Managing the lock table | `GAPPS_locktable` |
| Parallel processing (Work Queue Manager) | `GWORK_intro` |

## Embedded Python & Python SDKs

| Topic | KEY |
|---|---|
| Intro to Embedded Python | `AFL_epython` |
| Using Embedded Python — prerequisites | `GEPYTHON_prereqs` |
| Install/import Python packages | `GEPYTHON_loadlib` |
| Run Embedded Python | `GEPYTHON_runpython` |
| Call Embedded Python from ObjectScript | `GEPYTHON_callpython` |
| Call IRIS from Embedded Python | `GEPYTHON_calliris` |
| Bridge ObjectScript & Python data | `GEPYTHON_sharedata` |
| Embedded Python in productions | `GEPYTHON_productions` |
| Flexible Python runtime | `GEPYTHON_flexible` |
| `iris` Python module reference | `GEPYTHON_reference` |
| Native SDK for Python (intro) | `BPYNAT_about` |
| Native SDK — calling methods | `BPYNAT_call` |
| Native SDK — globals | `BPYNAT_globals` |
| Python DB-API (intro) | `BPYDBAPI_about` |
| Python DB-API quick reference | `BPYDBAPI_refapi` |
| Orientation for Python developers | `GPYDEV_intro` |

## External language servers (Java/.NET/etc.)

| Topic | KEY |
|---|---|
| Intro to external servers | `BEXTSERV_intro` |
| Working with external languages | `BEXTSERV_coding` |
| `$system.external` quick reference | `BEXTSERV_refapi` |

## Interoperability / HL7 / FHIR (IRIS for Health)

| Topic | KEY |
|---|---|
| HL7 Message Analyzer | `EHL7T_analyzer` |
| HL7 Production Generator | `EHL7T_generator` |
| HL7 DTL Generator | `EHL7T_dtlgenerator` |
| Embedded Python in productions | `GEPYTHON_productions` |

> The full Interoperability book set (Introducing Productions, Developing
> Productions, Programming Business Services/Processes/Operations, Routing HL7,
> FHIR Support) sits lower in the `ALL` catalog. Open `?KEY=ALL` and expand
> **Interoperability** / **FHIR**, or search the doc site for the component class
> (e.g. "EnsLib.HL7.Service.TCPService", "HS.FHIRServer"). Class signatures are in
> the Class Reference (`ACLASSREF`).

## Healthcare: IHE, SDA, CDA, FHIR (IRIS for Health)

Verified against the live IRIS for Health 2026.1 navigation. `HS.*` classes are in
the `HSLIB` library namespace; check exact signatures in Documatic (`ACLASSREF`).

| Topic | KEY |
|---|---|
| IRIS for Health overview | `AHXIHOVW` |
| Data Transformations in Healthcare Products (SDA hub) | `AHXDT` |
| SDA — About | `HXSDA_ch_about` |
| SDA — Documents | `HXSDA_ch_sda` |
| SDA — Customizing | `HXSDA_ch_sda_custom` |
| CDA Interoperability with SDA — Annotations | `HXCDA_ch_cda_sda_annotations` |
| CDA Interoperability with SDA — Customizing XSL | `HXCDA_ch_custom_transform` |
| FHIR overview & architecture — components | `HXFHIROVW_fhir_components` |
| FHIR server — introduction | `HXFHIROVW_server_intro` |
| Using FHIR Productions — interop productions for FHIR | `HXFHIRPROD_production` |
| Using FHIR Productions — FHIR Adapter (no repository) | `HXFHIRPROD_fhir_adapter` |
| Using FHIR Productions — SDA↔FHIR transformations | `HXFHIRPROD_transforms` |
| IHE Use Cases — contents | `HXIHE` |
| IHE Use Cases — introduction | `HXIHE_CH_USE_CASES` |
| IHE — XDS.b Provide & Register | `HXIHE_IHE_SCENARIOS_XDSB_DOCUMENT_PNR` |
| IHE — XDS.b Query / Retrieve | `HXIHE_IHE_scenarios_XDSb_query` |
| IHE — XCA query/retrieve across communities | `HXIHE_IHE_scenarios_XCA_initiate` |
| IHE — PIX/PDQ against an EMPI | `HXIHE_IHE_scenarios_query_EMPI` |
| IHE — generate C-CDA from HL7 | `HXIHE_IHE_SCENARIOS_GENERATE_CCD_HL7` |
| IHE — registry settings for IHE communication | `HXIHE_CH_REGISTRY_SETTINGS` |
| IHE — Test Utility | `HXIHE_CH_IHE_TEST_UTILITY` |

Key library classes (verify in Documatic for your version):
`HS.SDA3.Container`; `HS.FHIR.DTL.Util.API.Transform.SDA3ToFHIR` /
`...FHIRToSDA3`; `HS.FHIR.DTL.Util.HC.SDA3.FHIR.Process`;
`HS.Gateway.HL7.HL7ToSDA3`; `HS.FHIRServer.Interop.Service`;
`HS.IHE.XDSb.Repository.Services` / `.Repository.Process` /
`.DocumentSource.Operations`, `HS.HC.IHE.XDSb.Registry.Operations`.

## Developer tools, testing, source control

| Topic | KEY |
|---|---|
| Connecting an IDE (VS Code / Studio) | `AB_idesetup` |
| Source control integration | `ASC` |
| ObjectScript Shell | `GCLI_intro` |
| Code samples | `ASAMPLES` |
| Class Reference | `ACLASSREF` |
| Package Manager (IPM/zpm) | `AIPM` |
| Management Portal — Classes page | `ACLS` |
| Management Portal — Routines page | `AROU` |
| Management Portal — Globals page | `AGBL` |
| %UnitTest — about | `GUNITTEST_about` |
| %UnitTest — creating tests | `GUNITTEST_create` |
| %UnitTest — executing tests | `GUNITTEST_execute` |
| %UnitTest — viewing results | `GUNITTEST_results` |
| Code Scanner | `ACODESCAN` |

---

### How to verify a class or method signature

The Class Reference (`ACLASSREF`) documents every library class (`%Library.*`,
`%SQL.*`, `%Stream.*`, `Ens.*`, `EnsLib.*`, `HS.*`) with its properties, methods,
parameters, and inheritance. When unsure whether a method exists or what it
returns, check the Class Reference for that class rather than guessing.
