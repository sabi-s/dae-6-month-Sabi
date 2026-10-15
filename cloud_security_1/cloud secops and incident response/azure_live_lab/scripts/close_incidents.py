"""
Triage decisions for the Sentinel incidents raised on 15 Oct 2026: add the analyst comment, then close with classification.
Reads the incident again after commenting so the close uses the current etag. Cost: $0.
"""
import datetime as dt
import json
import os
import uuid

from ir_tests import SI, SIV, log, minutes, now, rest

DECISIONS = {
    "HVMC - Privileged Azure role assigned (Owner / Contributor / User Access Administrator)": dict(
        classification="BenignPositive", reason="SuspiciousButExpected",
        comment=("Triage (PB-02): User Access Administrator was granted at 17:06 UTC to the Microsoft Sentinel service principal, scoped to "
                 "HVMC-SecOps-LAW / SecurityInsights solution only, as a side effect of onboarding Sentinel (change HVMC-CHG-02). Caller verified "
                 "(Global Admin via Azure CLI); no human principal received privileged rights. Expected platform behaviour - closed.")),
    "HVMC - NSG inbound rule opened to the Internet": dict(
        classification="FalsePositive", reason="IncorrectAlertLogic",
        comment=("Triage (PB-01): the rule written at 18:00:49 UTC was Deny-Internet-Inbound-Data (Inbound DENY from Internet), approved "
                 "change HVMC-CHG-04 / IR test. The Activity Log event carried no request body, and the rule treats a missing body as suspicious, "
                 "so a hardening change raised a High incident. Detection tuned: severity is now computed per event (High only when the body "
                 "shows an Internet allow rule; Medium 'verify' when the body is missing).")),
    "HVMC - NSG rule change on hvmc-data-nsg: rule body not logged - verify access and direction": dict(
        classification="BenignPositive", reason="SuspiciousButExpected",
        comment=("Triage (PB-01, tuned rule): verified with az network nsg rule show - Deny-Internet-Inbound-Data is Inbound DENY from Internet, "
                 "approved change HVMC-CHG-04. The tuned detection correctly rated the event Medium 'verify' instead of High. Closed.")),
    "HVMC - ePHI storage keys retrieved or storage exposure changed": dict(
        classification="BenignPositive", reason="SuspiciousButExpected",
        comment=("Triage (PB-03): single event REGENERATEKEY on hvmcehrstorage at 18:07:49 UTC by the Global Admin via Azure CLI "
                 "(correlation 86be22da) - this was the PB-03 containment step (secondary key rotated). Duplicate incidents #5/#7/#8 came "
                 "from a 15-min look-back on a 5-min schedule; incident grouping (all entities, 5 h) enabled on all rules at 18:4x UTC.")),
}
DUPLICATE_NOTE = (" Duplicate of the same event (one NSG write at 18:00:50 UTC, correlation d1943137); incident grouping now enabled.")


def close_all():
    out = []
    old = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence", "ir_tests", "incidents_closed.json")
    if os.path.exists(old):
        out = json.load(open(old))
    for inc in rest("get", f"{SI}/incidents?{SIV}")["value"]:
        p = inc["properties"]
        d = DECISIONS.get(p["title"])
        if d and p["incidentNumber"] == 6:                 # second incident for the same NSG event
            d = dict(d, comment=d["comment"] + DUPLICATE_NOTE)
        if not d or p["status"] == "Closed":
            continue
        rest("put", f"{SI}/incidents/{inc['name']}/comments/{uuid.uuid4()}?{SIV}", {"properties": {"message": d["comment"]}})
        cur = rest("get", f"{SI}/incidents/{inc['name']}?{SIV}")            # fresh etag after the comment
        cp = cur["properties"]
        rest("put", f"{SI}/incidents/{inc['name']}?{SIV}", {"etag": cur["etag"], "properties": {
            "title": cp["title"], "severity": cp["severity"], "status": "Closed", "classification": d["classification"],
            "classificationReason": d["reason"], "classificationComment": d["comment"][:1000]}})
        closed = now()
        out.append(dict(number=p["incidentNumber"], title=p["title"], severity=p["severity"], created=p["createdTimeUtc"][:19] + "Z",
                        closed=closed, minutes_open=minutes(p["createdTimeUtc"], closed), classification=f'{d["classification"]} / {d["reason"]}'))
        log(f"incident #{p['incidentNumber']} closed as {d['classification']}")
    return out


if __name__ == "__main__":
    res = close_all()
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence", "ir_tests", "incidents_closed.json")
    json.dump(res, open(path, "w"), indent=1)
    print(json.dumps(res, indent=1))
