/// __DESC__  Custom converter business operation (IRIS for Health) that bridges
/// FHIR and SDA using the shipped transform APIs. Requires HS.* (HSLIB) — only
/// available in health-enabled namespaces. For a pure SDA->FHIR step in a
/// production you can instead just add HS.FHIR.DTL.Util.HC.SDA3.FHIR.Process.
Class __PKG__.__CLASS__ Extends Ens.BusinessOperation
{

Parameter INVOCATION = "Queue";

/// FHIR (stream) -> SDA container.
Method FhirToSda(pRequest As Ens.StreamContainer, Output pResponse As Ens.Response) As %Status
{
    Set sc = $$$OK
    Try {
        Set transform = ##class(HS.FHIR.DTL.Util.API.Transform.FHIRToSDA3).TransformStream(pRequest.Stream, "R4", "JSON")
        Set container = transform.container     // HS.SDA3.Container
        // ... route/store the SDA container ...
        Set pResponse = ##class(Ens.Response).%New()
    }
    Catch ex {
        Set sc = ex.AsStatus()
    }
    Return sc
}

/// SDA container -> FHIR Bundle.
Method SdaToFhir(pRequest As HS.SDA3.Container, Output pResponse As Ens.Response) As %Status
{
    Set sc = $$$OK
    Try {
        Set transform = ##class(HS.FHIR.DTL.Util.API.Transform.SDA3ToFHIR).TransformContainer(pRequest, "R4")
        Set bundle = transform.bundle           // FHIR Bundle (dynamic object)
        // ... send the bundle to a FHIR endpoint ...
        Set pResponse = ##class(Ens.Response).%New()
    }
    Catch ex {
        Set sc = ex.AsStatus()
    }
    Return sc
}

XData MessageMap
{
<MapItems>
  <MapItem MessageType="Ens.StreamContainer">
    <Method>FhirToSda</Method>
  </MapItem>
  <MapItem MessageType="HS.SDA3.Container">
    <Method>SdaToFhir</Method>
  </MapItem>
</MapItems>
}

}
