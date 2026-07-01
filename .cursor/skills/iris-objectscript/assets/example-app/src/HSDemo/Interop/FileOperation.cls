/// Business operation that writes incoming patient messages to a file via the
/// File outbound adapter. Routing of message class -> handler is done in the
/// MessageMap; the handler returns %Status so the engine can retry on failure.
Class HSDemo.Interop.FileOperation Extends Ens.BusinessOperation
{

Parameter ADAPTER = "EnsLib.File.OutboundAdapter";

/// Default directory; configurable per-item in the production.
Parameter SETTINGS = "Filename:Basic";

Property Filename As %String [ InitialExpression = "patients.txt" ];

Method WritePatient(pRequest As HSDemo.Interop.PatientMessage, Output pResponse As Ens.Response) As %Status
{
    Set line = pRequest.MRN _ "|" _ pRequest.LastName _ "|" _ pRequest.FirstName _ $Char(13, 10)
    Set sc = ..Adapter.PutString(..Filename, line)
    If $$$ISERR(sc) Return sc
    Set pResponse = ##class(Ens.Response).%New()
    $$$LOGINFO("Wrote patient " _ pRequest.MRN _ " to " _ ..Filename)
    Return $$$OK
}

XData MessageMap
{
<MapItems>
  <MapItem MessageType="HSDemo.Interop.PatientMessage">
    <Method>WritePatient</Method>
  </MapItem>
</MapItems>
}

}
