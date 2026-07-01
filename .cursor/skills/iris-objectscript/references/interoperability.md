# Interoperability, HL7, FHIR & REST Reference

IRIS interoperability ("productions") moves and transforms messages between
systems. IRIS for Health adds HL7 v2, FHIR, and IHE libraries. This file covers
production structure, the business host base classes, messages, adapters, data
transformations (DTL), HL7 v2, FHIR, and REST/CSP web services.

Official docs: *Interoperability* book set — *Introducing Interoperability
Productions*, *Developing Productions*, *Programming Business Services/Processes/
Operations*; *HL7 Version 2 Productions*; *FHIR* (IRIS for Health). See `doc-map.md`.

## Contents
1. Production architecture
2. The production class
3. Business services
4. Business operations
5. Business processes (incl. BPL)
6. Messages
7. Adapters
8. Data transformations (DTL)
9. HL7 v2
10. FHIR (IRIS for Health)
11. REST services (%CSP.REST)
12. Logging, settings, error handling

---

## 1. Production architecture

A **production** is a configured set of **business hosts** connected by
**messages**, hosted by the interoperability engine (formerly Ensemble).

```
  inbound → [Business Service] → [Business Process] → [Business Operation] → outbound
            (adapter in)         (routing/orchestration) (adapter out)
```

- **Business Service (BS)** — entry point; receives data from outside (via an
  inbound adapter or a direct call) and sends a request message into the production.
- **Business Process (BP)** — orchestration/routing/business logic; receives and
  sends messages, can call multiple hosts, maintains state across async replies.
- **Business Operation (BO)** — exit point; sends data to an external system (via
  an outbound adapter).
- **Messages** — typed objects (`Ens.Request`/`Ens.Response`) passed between hosts.
- **Adapters** — reusable I/O for files, TCP, HTTP, SQL, email, FTP, etc.

Each host runs as one or more jobs; messages are persisted, traceable, and
replayable in the Management Portal (Interoperability → View Messages / Visual Trace).

## 2. The production class

```objectscript
Class MyApp.Msg.Production Extends Ens.Production
{
XData ProductionDefinition
{
<Production Name="MyApp.Msg.Production" LogGeneralTraceEvents="false">
  <Item Name="HL7 In"  ClassName="EnsLib.HL7.Service.TCPService" Enabled="true">
    <Setting Target="Port" Value="7001"/>
    <Setting Target="TargetConfigNames" Value="Router"/>
  </Item>
  <Item Name="Router" ClassName="EnsLib.HL7.MsgRouter.RoutingEngine" Enabled="true"/>
  <Item Name="File Out" ClassName="EnsLib.HL7.Operation.FileOperation" Enabled="true"/>
</Production>
}
}
```

- The production is defined as an `XData ProductionDefinition` block listing
  `<Item>`s (the hosts) and their `<Setting>`s. The portal edits this for you.
- `TargetConfigNames` wires a host's output to the next host(s) by config name.

## 3. Business services

```objectscript
Class MyApp.Msg.FileService Extends Ens.BusinessService
{
Parameter ADAPTER = "EnsLib.File.InboundAdapter";

Method OnProcessInput(pInput As %Stream.Object, pOutput As %RegisteredObject) As %Status
{
    Set request = ##class(MyApp.Msg.OrderRequest).%New()
    Set request.Payload = pInput.Read(pInput.Size)
    Return ..SendRequestSync("Router", request, .response)
}
}
```

- Declare the inbound `ADAPTER` parameter (or use a "pass-through"/direct service).
- Implement `OnProcessInput(pInput, pOutput)` — the adapter calls it per inbound item.
- Send into the production with `..SendRequestSync(target, request, .response)` or
  `..SendRequestAsync(target, request)`.
- Return `%Status`; a bad status makes the framework retry/suspend per settings.

## 4. Business operations

```objectscript
Class MyApp.Msg.RestOperation Extends Ens.BusinessOperation
{
Parameter ADAPTER = "EnsLib.HTTP.OutboundAdapter";
Parameter INVOCATION = "Queue";

Method PostOrder(pRequest As MyApp.Msg.OrderRequest, Output pResponse As Ens.Response) As %Status
{
    Set sc = ..Adapter.Post(.httpResponse, , pRequest.Payload)
    If $$$ISERR(sc) Return sc
    Set pResponse = ##class(Ens.Response).%New()
    Return $$$OK
}

XData MessageMap
{
<MapItems>
  <MapItem MessageType="MyApp.Msg.OrderRequest"><Method>PostOrder</Method></MapItem>
</MapItems>
}
}
```

- Declare the outbound `ADAPTER`; call it via `..Adapter.<verb>(...)`.
- A `MessageMap` XData routes each incoming message **class** to a handler method.
- Handler signature: `(pRequest As <MsgClass>, Output pResponse As <MsgClass>) As %Status`.

## 5. Business processes (incl. BPL)

Two styles:

- **ObjectScript BP** — extend `Ens.BusinessProcess`, implement `OnRequest`,
  `OnResponse`, `OnComplete`. Manage async replies and state in properties.
- **BPL BP** — extend `Ens.BusinessProcessBPL`; define the flow graphically /
  in a `BPL` XData block (`<process>…<call>…<transform>…<assign>…`). Preferred for
  multi-step orchestration with branching, timers, and async calls.

```objectscript
Class MyApp.Msg.OrderProcess Extends Ens.BusinessProcessBPL
{
XData BPL [ XMLNamespace = "http://www.intersystems.com/bpl" ]
{
<process request="MyApp.Msg.OrderRequest" response="Ens.Response">
  <sequence>
    <call name="Send" target="File Out" async="0">
      <request type="MyApp.Msg.OrderRequest"><assign property="callrequest" value="request"/></request>
    </call>
  </sequence>
</process>
}
}
```

## 6. Messages

- Request/response payloads are persistent classes extending `Ens.Request` /
  `Ens.Response` (both extend `Ens.MessageBody` / `%Persistent`).
- Define typed properties; the framework persists and traces each message.
- Use a single message class per logical operation; don't pass loose globals.

```objectscript
Class MyApp.Msg.OrderRequest Extends Ens.Request
{
Property OrderId As %String [ Required ];
Property Payload As %Stream.GlobalCharacter;
}
```

## 7. Adapters

Reusable connectors set via the `ADAPTER` parameter:

- Files: `EnsLib.File.InboundAdapter` / `OutboundAdapter`.
- TCP: `EnsLib.TCP.*`. HTTP: `EnsLib.HTTP.InboundAdapter` / `OutboundAdapter`.
- SQL: `EnsLib.SQL.InboundAdapter` / `OutboundAdapter`. Email: `EnsLib.EMail.*`.
- FTP: `EnsLib.FTP.*`. SOAP/REST helpers, Kafka, AMQP, etc.
- Inbound adapters poll/listen and call `OnProcessInput`; outbound adapters expose
  verbs (`.Post`, `.Get`, `.SendMessage`, `.ExecuteQuery`) called from the BO.

## 8. Data transformations (DTL)

DTL maps a source message to a target message declaratively. Extend
`Ens.DataTransformDTL` with a `DTL` XData block (the portal has a visual editor):

```objectscript
Class MyApp.DT.ADTtoOrder Extends Ens.DataTransformDTL
{
XData DTL [ XMLNamespace = "http://www.intersystems.com/dtl" ]
{
<transform sourceClass="EnsLib.HL7.Message" targetClass="MyApp.Msg.OrderRequest" create="new" language="objectscript">
  <assign property="target.OrderId" value="source.{PID:3(1).1}" action="set"/>
</transform>
}
}
```

- Reference HL7 fields with virtual-property paths like `{PID:3(1).1}` (segment:
  field(repeat).component).
- Use `<assign>`, `<if>`, `<foreach>`, `<code>`, `<subtransform>` for logic.
- Call from a routing rule, a BP `<transform>`, or `##class(MyApp.DT.X).Transform(src,.tgt)`.

## 9. HL7 v2 (IRIS for Health)

- Messages are `EnsLib.HL7.Message`; schemas describe segment/field structure.
- Services: `EnsLib.HL7.Service.TCPService` / `FileService` / `HTTPService` /
  `SOAPService`. Operations: `EnsLib.HL7.Operation.TCPOperation` / `FileOperation`
  / `HTTPOperation`.
- Routing: `EnsLib.HL7.MsgRouter.RoutingEngine` with routing rules (rule sets) that
  match on message structure and invoke transformations/targets.
- Build/inspect messages with virtual property paths (`{MSH:9.1}`,
  `{PID:5(1).1.1}`); `ImportFromString`/`OutputToString` (de)serialize ER7.
- Acknowledgements (ACK/NACK) are handled by the HL7 service/operation settings.

## 10. FHIR (IRIS for Health)

- IRIS for Health hosts a **FHIR server/repository** (`HS.FHIRServer.*`). Set up
  an endpoint with the FHIR Server configuration page or
  `##class(HS.FHIRServer.Installer).*`.
- Interact programmatically via `HS.FHIRServer.Service` / the REST interface; FHIR
  resources are JSON handled with dynamic objects (`%DynamicObject`/`%DynamicArray`).
- Use `%JSON.Adaptor` classes or the SDA ↔ FHIR transformation pipeline for
  mapping between internal models and FHIR resources.
- For consuming external FHIR, use the FHIR client classes (`HS.FHIRServer.RestClient`
  / interoperability HTTP operations) and FHIR interoperability components.

(FHIR APIs evolve across releases — confirm exact class names/signatures against
the version's docs via `doc-map.md` before relying on them.)

## 11. REST services (%CSP.REST)

Expose REST APIs by subclassing `%CSP.REST` and mapping routes in `XData UrlMap`:

```objectscript
Class MyApp.API.Main Extends %CSP.REST
{
Parameter CONTENTTYPE = "application/json";
Parameter CHARSET = "utf-8";

XData UrlMap [ XMLNamespace = "http://www.intersystems.com/urlmap" ]
{
<Routes>
  <Route Url="/patients/:id" Method="GET" Call="GetPatient"/>
  <Route Url="/patients"     Method="POST" Call="CreatePatient"/>
</Routes>
}

ClassMethod GetPatient(id As %String) As %Status
{
    Set patient = ##class(MyApp.Data.Patient).%OpenId(id, , .sc)
    If '$IsObject(patient) {
        Set %response.Status = ..#HTTP404NOTFOUND
        Return ..%WriteJSONStreamResponse({"error":"not found"})
    }
    #dim out As %DynamicObject = {"id":(patient.%Id()), "name":(patient.Name)}
    Write out.%ToJSON()
    Return $$$OK
}
}
```

- Handlers are class methods named in the routes; URL tokens (`:id`) map to args.
- Read the request via `%request` (`%request.Content`, `.Get("param")`); write the
  response with `Write`/`%response`. Use `%DynamicObject`/`%DynamicArray` and
  `%FromJSON`/`%ToJSON` for JSON.
- Set HTTP status via `%response.Status = ..#HTTP400BADREQUEST` etc.
- Deploy by creating a **web application** in the Management Portal that points its
  *Dispatch Class* at this `%CSP.REST` subclass (System Administration → Security →
  Applications → Web Applications). Secure it with the application's auth settings.
- For larger APIs prefer a spec-first approach with the API Management tooling
  (`%REST` / OpenAPI generation) where appropriate.

## 12. Logging, settings, error handling

- Log from any host with `$$$LOGINFO("msg")`, `$$$LOGWARNING(...)`,
  `$$$LOGERROR(...)`, `$$$LOGASSERT(...)` (from the `Ensemble` include) — entries
  appear in the Event Log.
- Expose configurable host settings with the `SETTINGS` parameter and properties;
  values are edited per-item in the portal.
- Return `%Status` from `On*` methods. The engine uses settings (retry count,
  retry interval, failure timeout, reply-code actions) to retry, suspend, or
  fail a message — design idempotent operations so retries are safe.
- Use the Visual Trace and Message Viewer to debug; every message and its
  transformations are persisted.

---

### Interoperability checklist

- [ ] Hosts extend the correct base (`Ens.BusinessService/Operation/Process[BPL]`).
- [ ] Data flows as typed `Ens.Request`/`Ens.Response` messages, not loose args.
- [ ] BO uses a `MessageMap`; transformations done in DTL, routing in rule sets.
- [ ] Adapters chosen from `EnsLib.*`; HL7 uses `EnsLib.HL7.*`, FHIR `HS.FHIRServer.*`.
- [ ] `On*` methods return `%Status`; operations are idempotent for safe retries.
- [ ] Logging via `$$$LOGINFO/WARNING/ERROR`; settings exposed via `SETTINGS`.
- [ ] REST dispatch class wired to a secured web application.
