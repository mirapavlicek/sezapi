/// REST API for the patient registry. Subclass of %CSP.REST with routes in
/// XData UrlMap. Wire this class as the Dispatch Class of a web application
/// (e.g. /csp/healthshare/<ns>/hsdemo or a dedicated /hsdemo app).
Class HSDemo.REST.API Extends %CSP.REST
{

Parameter CONTENTTYPE = "application/json";

Parameter CHARSET = "utf-8";

/// Emit permissive CORS headers for demo purposes.
Parameter HandleCorsRequest = 1;

XData UrlMap [ XMLNamespace = "http://www.intersystems.com/urlmap" ]
{
<Routes>
  <Route Url="/patients" Method="POST" Call="CreatePatient"/>
  <Route Url="/patients/:mrn" Method="GET" Call="GetPatient"/>
  <Route Url="/patients/:mrn/observations" Method="POST" Call="AddObservation"/>
  <Route Url="/patients/:mrn/observations/:code/mean" Method="GET" Call="GetMean"/>
</Routes>
}

/// POST /patients  body: {"mrn":"...","lastName":"...","firstName":"...","birthDate":"YYYY-MM-DD"}
ClassMethod CreatePatient() As %Status
{
    Try {
        Set body = ..GetBody()
        Set birth = ""
        If body.birthDate '= "" {
            Set birth = $ZDateH(body.birthDate, 3)   // ODBC date -> $Horolog
        }
        Set sc = ##class(HSDemo.Service.Registry).RegisterPatient(body.mrn, body.lastName, body.firstName, birth, .id)
        If $$$ISERR(sc) Return ..Error(400, $System.Status.GetErrorText(sc))
        Set %response.Status = ..#HTTP201CREATED
        Return ..WriteJSON({"id": (id), "mrn": (body.mrn)})
    }
    Catch ex {
        Return ..Error(500, ex.DisplayString())
    }
}

/// GET /patients/:mrn
ClassMethod GetPatient(mrn As %String) As %Status
{
    Set patient = ##class(HSDemo.Service.Registry).FindByMRN(mrn, .sc)
    If '$IsObject(patient) Return ..Error(404, "Patient not found")
    Set out = {}
    Set out.id = patient.%Id()
    Set out.mrn = patient.MRN
    Set out.fullName = patient.FullName
    Set out.status = patient.Status
    Set out.age = patient.GetAge()
    Return ..WriteJSON(out)
}

/// POST /patients/:mrn/observations  body: {"code":"8867-4","value":72,"unit":"/min"}
ClassMethod AddObservation(mrn As %String) As %Status
{
    Set body = ..GetBody()
    Set sc = ##class(HSDemo.Service.Registry).AddObservation(mrn, body.code, body.value, body.unit)
    If $$$ISERR(sc) Return ..Error(400, $System.Status.GetErrorText(sc))
    Set %response.Status = ..#HTTP201CREATED
    Return ..WriteJSON({"ok": 1})
}

/// GET /patients/:mrn/observations/:code/mean
ClassMethod GetMean(mrn As %String, code As %String) As %Status
{
    Set mean = ##class(HSDemo.Util.Stats).MeanObservation(mrn, code)
    Return ..WriteJSON({"mrn": (mrn), "code": (code), "mean": (mean)})
}

/// Parse the request body as a dynamic object; empty object if no body.
ClassMethod GetBody() As %DynamicObject [ Private ]
{
    If '$IsObject(%request.Content) || (%request.Content.Size = 0) Return {}
    Return ##class(%DynamicObject).%FromJSON(%request.Content)
}

/// Write a dynamic object/array as the JSON response.
ClassMethod WriteJSON(obj As %DynamicAbstractObject) As %Status [ Private ]
{
    Write obj.%ToJSON()
    Return $$$OK
}

/// Emit a JSON error with an HTTP status code.
ClassMethod Error(code As %Integer, message As %String) As %Status [ Private ]
{
    Set %response.Status = code _ $Case(code, 400:" Bad Request", 404:" Not Found", 500:" Internal Server Error", :"")
    Write {"error": (message)}.%ToJSON()
    Return $$$OK
}

}
