/// __DESC__  REST API. Wire as the Dispatch Class of a web application.
Class __PKG__.__CLASS__ Extends %CSP.REST
{

Parameter CONTENTTYPE = "application/json";

Parameter CHARSET = "utf-8";

XData UrlMap [ XMLNamespace = "http://www.intersystems.com/urlmap" ]
{
<Routes>
  <Route Url="/items" Method="GET" Call="ListItems"/>
  <Route Url="/items/:id" Method="GET" Call="GetItem"/>
  <Route Url="/items" Method="POST" Call="CreateItem"/>
</Routes>
}

ClassMethod ListItems() As %Status
{
    Set arr = []
    // ... populate arr ...
    Write arr.%ToJSON()
    Return $$$OK
}

ClassMethod GetItem(id As %String) As %Status
{
    // Set %response.Status = ..#HTTP404NOTFOUND  when missing
    Write {"id": (id)}.%ToJSON()
    Return $$$OK
}

ClassMethod CreateItem() As %Status
{
    Set body = ##class(%DynamicObject).%FromJSON(%request.Content)
    Set %response.Status = ..#HTTP201CREATED
    Write {"ok": 1}.%ToJSON()
    Return $$$OK
}

}
