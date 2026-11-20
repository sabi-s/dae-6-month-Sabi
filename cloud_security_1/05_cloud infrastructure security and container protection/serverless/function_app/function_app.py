"""
HVMC-LabResult-Func - returns one lab result document from the ePHI storage account.

Security design:
  * Identity: system-assigned managed identity + DefaultAzureCredential - no keys or connection strings anywhere.
  * Least privilege: the identity holds only "Storage Blob Data Reader" on the single container lab-results.
  * Network: outbound through VNet integration; the storage account is reachable only via its private endpoint.
  * Input validation on the result id; generic errors; audit log records the id and caller, never the PHI.
"""
import json
import logging
import os
import re

import azure.functions as func
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)     # caller needs a function key (plus Entra auth at the gateway)
RESULT_ID = re.compile(r"^LR-[0-9]{8}-[0-9]{4}$")                   # e.g. LR-20261015-0042
_blob = BlobServiceClient(account_url=os.environ["EPHI_ACCOUNT_URL"], credential=DefaultAzureCredential())
_container = _blob.get_container_client(os.environ.get("EPHI_CONTAINER", "lab-results"))


@app.route(route="labresult/{result_id}", methods=["GET"])
def labresult(req: func.HttpRequest) -> func.HttpResponse:
    rid = req.route_params.get("result_id", "")
    caller = req.headers.get("x-ms-client-principal-name", "unknown")
    if not RESULT_ID.match(rid):
        return _json(400, {"error": "invalid result id"})
    try:
        data = _container.get_blob_client(f"{rid}.json").download_blob().readall()
    except ResourceNotFoundError:
        logging.info(json.dumps({"event": "labresult_read", "id": rid, "caller": caller, "outcome": "not_found"}))
        return _json(404, {"error": "not found"})
    except Exception:                                                   # never leak internals to the client
        logging.exception("labresult_read_failed id=%s", rid)
        return _json(500, {"error": "internal error"})
    logging.info(json.dumps({"event": "labresult_read", "id": rid, "caller": caller, "outcome": "ok"}))
    return func.HttpResponse(data, status_code=200, mimetype="application/json",
                             headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


def _json(code, body):
    return func.HttpResponse(json.dumps(body), status_code=code, mimetype="application/json", headers={"Cache-Control": "no-store"})
