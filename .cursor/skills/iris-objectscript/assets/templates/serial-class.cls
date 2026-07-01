/// __DESC__  An embeddable value object (no own extent); stored inside the
/// persistent object that references it.
Class __PKG__.__CLASS__ Extends (%SerialObject, %JSON.Adaptor)
{

Property Line1 As %String(MAXLEN = 200);

Property City As %String(MAXLEN = 100);

Property PostalCode As %String(MAXLEN = 20);

}
