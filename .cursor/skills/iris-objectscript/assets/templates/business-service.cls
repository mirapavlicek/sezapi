/// __DESC__  Inbound business service. The adapter calls OnProcessInput per item.
Class __PKG__.__CLASS__ Extends Ens.BusinessService
{

Parameter ADAPTER = "EnsLib.File.InboundAdapter";

Method OnProcessInput(pInput As %Stream.Object, pOutput As %RegisteredObject) As %Status
{
    Set request = ##class(Ens.StringRequest).%New()
    Set request.StringValue = pInput.Read(pInput.Size)
    Return ..SendRequestSync("TargetConfigName", request, .response)
}

}
