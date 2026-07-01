# IHE Profiles & Clinical Interoperability (IRIS for Health)

How to build healthcare interoperability on InterSystems IRIS for Health: the IHE
profiles the product implements, the **SDA** clinical model that sits at the
center of every conversion, and the CDA ↔ SDA ↔ FHIR and HL7v2 → SDA pipelines —
including the exact library classes and the documentation page for each topic.

> These are IRIS for Health / Health Connect (and HealthShare) features. The
> `HS.*` classes live in the `HSLIB` library namespace and are available from
> health-enabled namespaces. They do **not** exist in plain InterSystems IRIS.
> Class names and method signatures evolve between versions — confirm against the
> Class Reference (Documatic) and the doc pages in `doc-map.md` for your version.

## Contents
1. The big picture: SDA as the interoperability hub
2. SDA — the InterSystems clinical data format
3. CDA ⇄ SDA (XSLT)
4. HL7 v2 → SDA
5. SDA ⇄ FHIR (DTL)
6. End-to-end conversions (CDA → FHIR, HL7 → C-CDA, …)
7. FHIR into a production (FHIR server vs FHIR Adapter)
8. IHE profiles and how they are implemented
9. Building & configuring an IHE production
10. Customizing transformations (upgrade-safe)

---

## 1. The big picture: SDA as the interoperability hub

InterSystems healthcare products do **not** write a direct transform for every
pair of standards. Instead everything is converted through one internal model,
**SDA** (Summary Document Architecture). To go from format A to format B you
convert A → SDA, then SDA → B, reusing the ready-made XSLTs, DTLs, and API methods
shipped with the product.

```
   CDA  ──XSLT──▶            ──DTL──▶  FHIR
                  ▶  SDA  ◀
   HL7 v2 ──code─▶  (HS.SDA3) ◀──DTL── FHIR
                  ◀──XSLT──            CDA
```

So "convert C-CDA v2.1 to FHIR" = CDA → SDA (XSLT) then SDA → FHIR (DTL).
See *Data Transformations in InterSystems Healthcare Products* (`AHXDT`).

## 2. SDA — the InterSystems clinical data format

- SDA represents a patient's clinical data. The current version is **SDA3**.
- The root object is **`HS.SDA3.Container`**; it holds streams/lists of clinical
  objects (`HS.SDA3.Patient`, `HS.SDA3.Encounter`, `HS.SDA3.Observation`,
  `HS.SDA3.Allergy`, `HS.SDA3.Medication`, …).
- SDA is XML-serializable, so you can import/export an SDA document and inspect it.
- It is extensible — you can add custom fields. Prefer the documented extension
  mechanism over editing shipped classes.

Docs: *SDA: InterSystems Clinical Data Format* — About SDA (`HXSDA_ch_about`),
SDA Documents (`HXSDA_ch_sda`), Customizing the SDA (`HXSDA_ch_sda_custom`).

## 3. CDA ⇄ SDA (XSLT)

CDA / C-CDA (HL7 v3 clinical XML documents) convert to and from SDA via XSLT
stylesheets shipped with the product.

- The transforms cover document types such as CCDA1, CCDA2, C32, and XDLAB.
- The **SDA/CDA Annotations** tool (Schema Documentation menu in the Management
  Portal) shows the field-level mappings — use it to find which CDA field maps to
  which SDA property.

Docs: *CDA Interoperability with SDA* — CDA and SDA Annotations
(`HXCDA_ch_cda_sda_annotations`), Customizing CDA XSL Transformations
(`HXCDA_ch_custom_transform`).

## 4. HL7 v2 → SDA

Convert an HL7 v2 message to SDA programmatically:

```objectscript
// pHL7 is an EnsLib.HL7.Message
Set sdaContainer = ##class(HS.Gateway.HL7.HL7ToSDA3).GetSDA(pHL7)
// sdaContainer is an HS.SDA3.Container you can then push to FHIR/CDA/storage
```

This is how an HL7 feed becomes a C-CDA or FHIR resource: HL7 → SDA (above) →
CDA (XSLT) or → FHIR (DTL). The "Generate a C-CDA Document from an HL7 Message"
use case walks through it (`HXIHE_IHE_SCENARIOS_GENERATE_CCD_HL7`).

## 5. SDA ⇄ FHIR (DTL)

SDA and FHIR convert via DTL transformations, exposed through two API classes
(both in the `HSLIB` namespace). Each returns a transform object that holds the
result.

**SDA → FHIR** — `HS.FHIR.DTL.Util.API.Transform.SDA3ToFHIR`:

```objectscript
#dim transform As HS.FHIR.DTL.Util.API.Transform.SDA3ToFHIR
Set transform = ##class(HS.FHIR.DTL.Util.API.Transform.SDA3ToFHIR).TransformContainer(
    sdaContainer,            // HS.SDA3.Container
    "R4")                    // target FHIR version, e.g. "STU3" / "R4"
Set fhirBundle = transform.bundle   // a FHIR Bundle (dynamic object) with refs resolved
```

**FHIR → SDA** — `HS.FHIR.DTL.Util.API.Transform.FHIRToSDA3`:

```objectscript
// From a %Stream (resource or bundle):
Set transform = ##class(HS.FHIR.DTL.Util.API.Transform.FHIRToSDA3).TransformStream(
    fhirStream,              // %Stream.Object containing the FHIR
    "R4",                    // fhirVersion: "STU3" / "R4"
    "JSON")                  // fhirFormat:  "JSON" / "XML"
Set sdaContainer = transform.container   // HS.SDA3.Container

// From a dynamic object: TransformObject(dynObj, version)
// Reuse for many payloads: instantiate once, call Transform() repeatedly.
```

In a **production**, you usually don't write this by hand: add the built-in
business process **`HS.FHIR.DTL.Util.HC.SDA3.FHIR.Process`** to convert an SDA
container/object into a FHIR Bundle as messages flow.

Docs: *Using FHIR Productions* — SDA-FHIR Transformations (`HXFHIRPROD_transforms`).

## 6. End-to-end conversions

Compose the steps above:

| From → To | Path |
|---|---|
| C-CDA → FHIR | CDA →(XSLT)→ SDA →(DTL)→ FHIR |
| FHIR → C-CDA | FHIR →(DTL)→ SDA →(XSLT)→ CDA |
| HL7 v2 → C-CDA | HL7 →(`HL7ToSDA3.GetSDA`)→ SDA →(XSLT)→ CDA |
| HL7 v2 → FHIR | HL7 → SDA → FHIR |

Each leg reuses shipped transforms, so a converter service is mostly wiring, not
hand-written mapping.

## 7. FHIR into a production (two front doors)

To accept FHIR requests into an interoperability production:

1. **FHIR server route** — `HS.FHIRServer.Interop.Service`: requests hitting a
   configured FHIR server endpoint are delivered into the production as messages.
   Use when you run a FHIR server/repository.
2. **FHIR Adapter (no repository)** — install the *FHIR Adapter for
   Interoperability Productions*; it creates a REST endpoint plus two hosts:
   - `InteropService` — business service that receives FHIR requests;
   - `InteropOperation` — placeholder business operation (returns HTTP 501 until
     you extend/replace it). Implement your logic here, or proxy to an external
     FHIR endpoint.

Docs: *Using FHIR Productions* — Interoperability Productions for FHIR
(`HXFHIRPROD_production`), FHIR Adapter (`HXFHIRPROD_fhir_adapter`); FHIR Server
intro (`HXFHIROVW_server_intro`), FHIR components (`HXFHIROVW_fhir_components`).

## 8. IHE profiles and how they are implemented

IRIS for Health implements IHE profiles as production components (business
services, processes, and operations) plus the Service/Configuration registries.

Supported in IRIS for Health: **XDS.b**, **XCA**, **PIX**, **PDQ**, with **ATNA**
auditing; Health Connect additionally supports **MHD** (FHIR-based document
access). (The mobile/FHIR-flavored profiles PIXm/PDQm/MHD are FHIR-based.)

| Profile | Purpose | Representative classes |
|---|---|---|
| **XDS.b** | Share documents in an Affinity Domain (Provide & Register, Query, Retrieve) | `HS.IHE.XDSb.Repository.Services` (SOAP service), `HS.IHE.XDSb.Repository.Process` (BP), `HS.HC.IHE.XDSb.Registry.Operations` (registry BO), `HS.IHE.XDSb.DocumentSource.Operations` (builds Provide & Register from a CDA stream) |
| **XCA** | Query/retrieve documents across communities / affinity domains | `HS.IHE.XCA.*` gateway components |
| **PIX / PDQ** | Patient identity cross-reference / demographics query against an MPI/EMPI | PIX & PDQ business operations (see the EMPI use case) |
| **ATNA** | Audit logging of IHE transactions | ATNA auditing settings on the hosts |

The repository stores a document and sends an XDS.b register request to the
registry; PIX/PDQ obtain the MPI ID. Confirm exact class names per version in the
Class Reference (Documatic).

Docs: *IHE Use Cases* — contents (`HXIHE`), intro (`HXIHE_CH_USE_CASES`),
Provide & Register (`HXIHE_IHE_SCENARIOS_XDSB_DOCUMENT_PNR`), Query/Retrieve
(`HXIHE_IHE_scenarios_XDSb_query`), XCA (`HXIHE_IHE_scenarios_XCA_initiate`),
PIX/PDQ against an EMPI (`HXIHE_IHE_scenarios_query_EMPI`), Generate C-CDA from
HL7 (`HXIHE_IHE_SCENARIOS_GENERATE_CCD_HL7`).

## 9. Building & configuring an IHE production

The IHE components are shipped — you enable and configure them rather than coding
them from scratch:

1. **Production** running with the relevant IHE hosts enabled (e.g. for XDS.b
   provide & register, enable `HS.IHE.XDSb.DocumentSource.Operations`).
2. **Configuration Registry** — set `AffinityDomain` and `HomeCommunity` (minimum
   for IHE communication). See *Registry Settings for IHE Communication*
   (`HXIHE_CH_REGISTRY_SETTINGS`).
3. **Service Registry** — set the endpoints: the PDQ supplier endpoint, the XDS
   **registry** endpoint (one per Affinity Domain), and the **repository**
   endpoint(s) (there may be several).
4. **Test** with the IHE Test Utility: enable the `HS.Test.Service` business
   service; it exercises PIX, PDQ, PIX Merge, and XDS.b Provide&Register / Query /
   Retrieve. See *Using the IHE Test Utility* (`HXIHE_CH_IHE_TEST_UTILITY`).
5. **Debugging**: enable `TraceOperations` on the PIX/PDQ/XDS.b operations while
   testing — and turn it off before production.

## 10. Customizing transformations (upgrade-safe)

- **Do not edit the shipped XSLTs/DTLs in place** — they are replaced on upgrade.
  Create custom XSLs in a custom directory (kept across upgrades) and point the
  transform at them; subclass/override DTLs for FHIR. See Customizing CDA XSL
  Transformations (`HXCDA_ch_custom_transform`) and Customizing the SDA
  (`HXSDA_ch_sda_custom`).
- Extend SDA with custom properties through the documented extension points rather
  than modifying `HS.SDA3.*` classes directly.
- See `assets/templates/fhir-transform-operation.cls` for a custom business
  operation that converts between FHIR and SDA using the API classes above.

---

### Clinical interop checklist

- [ ] Routing data through **SDA** as the hub, reusing shipped XSLT/DTL transforms.
- [ ] FHIR↔SDA via `HS.FHIR.DTL.Util.API.Transform.SDA3ToFHIR` /
      `...FHIRToSDA3` (or the built-in `HS.FHIR.DTL.Util.HC.SDA3.FHIR.Process` in a production).
- [ ] HL7→SDA via `HS.Gateway.HL7.HL7ToSDA3.GetSDA()`.
- [ ] FHIR ingress via `HS.FHIRServer.Interop.Service` or the FHIR Adapter
      (`InteropService` / `InteropOperation`).
- [ ] IHE: enabled the shipped `HS.IHE.*` hosts; set AffinityDomain/HomeCommunity
      and the Service Registry endpoints; ATNA auditing on.
- [ ] Customizations made in custom XSL dirs / subclassed DTLs — shipped artifacts untouched.
- [ ] Verified class names/signatures in Documatic for the target version.
