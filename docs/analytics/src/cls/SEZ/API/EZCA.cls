/// EZCA 2 – Elektronická certifikační autorita API v1.0.0
/// Base URL: /ezca2
Class SEZ.API.EZCA Extends %RegisteredObject
{

Property Client As SEZ.API.HttpClient [ Required ];

Parameter BASEPATH = "/ezca2";

Method %OnNew(pConfig As SEZ.API.Config) As %Status
{
    Set ..Client = ##class(SEZ.API.HttpClient).%New(pConfig)
    Quit $$$OK
}

// ==========================================================================
// PODEPISOVÁNÍ
// ==========================================================================

/// Podepíše dokument elektronickým podpisem
/// pDocumentType: 0=ARCHIVATION, 1=CADES, 2=PADES, 3=XADES, ...
Method PodpisDokumentu(pBase64Content As %String, pDocumentType As %Integer, pFileName As %String, pSourceSystem As %String, pCertificateId As %String, pCryptedPassword As %String, pStorageId As %String, pTimestamp As %Boolean = 1, pAsync As %Boolean = 0, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "authentication": {"userLogin": ""},
        "document": {
            "documentContent": (pBase64Content),
            "documentType": (pDocumentType),
            "fileName": (pFileName),
            "sourceSystem": (pSourceSystem),
            "isSignatureWithTimestamp": (pTimestamp),
            "certificateId": (pCertificateId),
            "cryptedPassword": (pCryptedPassword),
            "storageId": (pStorageId)
        }
    }
    Set path = ..#BASEPATH_$Select(pAsync:"/api/signasync/document", 1:"/api/sign/document")
    Quit ..Client.Post(path, body, .pResponse)
}

/// Podepíše hash
Method PodpisHashe(pHashValue As %String, pHashAlgorithm As %Integer, pFileName As %String, pSourceSystem As %String, pCertificateId As %String, pCryptedPassword As %String, pStorageId As %String, pAsync As %Boolean = 0, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "authentication": {"userLogin": ""},
        "hash": {
            "hashValue": (pHashValue),
            "hashAlgorithm": (pHashAlgorithm),
            "fileName": (pFileName),
            "sourceSystem": (pSourceSystem),
            "certificateId": (pCertificateId),
            "cryptedPassword": (pCryptedPassword),
            "storageId": (pStorageId)
        }
    }
    Set path = ..#BASEPATH_$Select(pAsync:"/api/signasync/hash", 1:"/api/sign/hash")
    Quit ..Client.Post(path, body, .pResponse)
}

// ==========================================================================
// ČASOVÉ RAZÍTKO
// ==========================================================================

/// Orazítkuje dokument časovým razítkem
Method RazitkovaniDokumentu(pBase64Content As %String, pDocumentType As %Integer, pFileName As %String, pSourceSystem As %String, pTsaId As %String, pStorageId As %String, pAsync As %Boolean = 0, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "authentication": {"userLogin": ""},
        "document": {
            "documentContent": (pBase64Content),
            "documentType": (pDocumentType),
            "fileName": (pFileName),
            "sourceSystem": (pSourceSystem),
            "tsaId": (pTsaId),
            "storageId": (pStorageId)
        }
    }
    Set path = ..#BASEPATH_$Select(pAsync:"/api/stampasync/document", 1:"/api/stamp/document")
    Quit ..Client.Post(path, body, .pResponse)
}

// ==========================================================================
// VALIDACE
// ==========================================================================

/// Validuje podpis dokumentu
/// pValidationType: 0=ADES, 1=DOCX, 2=XLSX, 3=EML, 4=MSG
Method ValidujDokument(pSignedContent As %String, pSignedFileName As %String, pOriginalContent As %String, pOriginalFileName As %String, pValidationType As %Integer, pSourceSystem As %String, pStorageId As %String, pAsync As %Boolean = 0, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "authentication": {"userLogin": ""},
        "document": {
            "signedDocumentContent": (pSignedContent),
            "signedFileName": (pSignedFileName),
            "originalDocumentContent": (pOriginalContent),
            "originalFileName": (pOriginalFileName),
            "documentValidationType": (pValidationType),
            "sourceSystem": (pSourceSystem),
            "storageId": (pStorageId)
        }
    }
    Set path = ..#BASEPATH_$Select(pAsync:"/api/validateasync/document", 1:"/api/validate/document")
    Quit ..Client.Post(path, body, .pResponse)
}

// ==========================================================================
// DOKUMENTY A CERTIFIKÁTY
// ==========================================================================

/// Vytvoří dokument v EZCA
Method VytvorDokument(pDokument As %DynamicObject, pAsync As %Boolean = 0, Output pResponse As %DynamicObject) As %Status
{
    Set path = ..#BASEPATH_$Select(pAsync:"/api/createasync/document", 1:"/api/create/document")
    Quit ..Client.Post(path, pDokument, .pResponse)
}

/// Informace o dokumentu
Method InfoDokumentu(pId As %String, pAsync As %Boolean = 0, Output pResponse As %DynamicObject) As %Status
{
    Set path = ..#BASEPATH_$Select(pAsync:"/api/infoasync/document/", 1:"/api/info/document/")_pId
    Quit ..Client.Get(path, , .pResponse)
}

/// Výpis certifikátů
Method VypisCertifikatu(pStorageId As %String, pOwnerId As %String = "", pAsync As %Boolean = 0, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "authentication": {"userLogin": ""},
        "owner": {"storageId": (pStorageId)}
    }
    If pOwnerId '= "" Set body.owner.id = pOwnerId
    Set path = ..#BASEPATH_$Select(pAsync:"/api/listasync/certificates", 1:"/api/list/certificates")
    Quit ..Client.Post(path, body, .pResponse)
}

/// Vytvoří XAdES obálku
Method VytvorXades(pHashAlgorithm As %Integer, pStorageId As %String, pValues As %DynamicArray, pAsync As %Boolean = 0, Output pResponse As %DynamicObject) As %Status
{
    Set body = {
        "authentication": {"userLogin": ""},
        "xadesEnvelope": {
            "hashAlgorithm": (pHashAlgorithm),
            "storageId": (pStorageId),
            "valuesList": (pValues)
        }
    }
    Set path = ..#BASEPATH_$Select(pAsync:"/api/createasync/xades", 1:"/api/create/xades")
    Quit ..Client.Post(path, body, .pResponse)
}

/// Kontrola zdraví služby
Method HealthCheck(Output pOk As %Boolean) As %Status
{
    Set sc = ..Client.Get(..#BASEPATH_"/simple-health", , .resp)
    Set pOk = (..Client.LastStatusCode = 200)
    Quit sc
}

}
