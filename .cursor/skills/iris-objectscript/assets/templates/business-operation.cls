/// __DESC__  Outbound business operation. MessageMap routes each message class
/// to a handler that returns %Status (so the engine can retry on failure).
Class __PKG__.__CLASS__ Extends Ens.BusinessOperation
{

Parameter ADAPTER = "EnsLib.HTTP.OutboundAdapter";

Parameter INVOCATION = "Queue";

Method SendItem(pRequest As Ens.Request, Output pResponse As Ens.Response) As %Status
{
    // Set sc = ..Adapter.Post(.httpResponse, , pRequest....)
    Set pResponse = ##class(Ens.Response).%New()
    Return $$$OK
}

XData MessageMap
{
<MapItems>
  <MapItem MessageType="Ens.Request">
    <Method>SendItem</Method>
  </MapItem>
</MapItems>
}

}
