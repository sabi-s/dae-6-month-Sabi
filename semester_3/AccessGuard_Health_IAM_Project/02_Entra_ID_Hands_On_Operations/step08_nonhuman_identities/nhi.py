"""
Step 8 - Non-human identities (NHI) in Microsoft Entra ID (Free tier, $0).   Change HVMC-IAM-CHG-108.

Creates one workload identity the safe way and proves it is least-privilege:
  HVMC Lab Results Sync  - a background service that needs to know who is in the laboratory groups
    - app registration + service principal, single-tenant, an owner, tags and a register entry
    - credential: an X.509 CERTIFICATE issued by HVMC Issuing CA 1 (rubric 4 PKI) - no client secret
    - permission: Microsoft Graph GroupMember.Read.All (application) only, granted by admin consent
    - test: signs in with the certificate (OAuth client credentials + signed JWT assertion), then
        reads a lab group's members          -> must WORK  (200)
        lists all users                      -> must FAIL  (403, not granted)
        changes a group                      -> must FAIL  (403, read-only)

    python3 nhi.py                 # dry run: NHI inventory + plan, no changes
    python3 nhi.py --apply         # create, consent, test, write the register
    python3 nhi.py --test          # re-run only the sign-in test
The private key stays in secrets/ (mode 0600, git-ignored); later it moves into Azure Key Vault.
Evidence goes to evidence/ (git-ignored: object IDs).
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "step2_rbac_v2"))
from rbac_v2 import graph  # noqa: E402

REPO_PKI = os.path.expanduser("~/Desktop/dae 6month_Sabi/cryptography_1/public_key_crypto")
EVID, SECRETS = os.path.join(HERE, "evidence"), os.path.join(HERE, "secrets")
TICKET = "HVMC-IAM-CHG-108"
APP_NAME = "HVMC Lab Results Sync"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
GROUP_MEMBER_READ_ALL = "98830695-27a2-44f7-8c18-0c3ebc9698f6"
LAB_GROUP = "SG-Lab-LIS-RW"
UTC = dt.timezone.utc


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def save(name, data):
    os.makedirs(EVID, exist_ok=True)
    path = os.path.join(EVID, f"{dt.datetime.now():%Y%m%d_%H%M%S}_{name}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


def paged(url):
    out = []
    while url:
        p = graph("get", url)
        out += p["value"]
        nl = p.get("@odata.nextLink")
        url = nl.split("graph.microsoft.com/v1.0", 1)[1] if nl else None
    return out


# ---------------------------------------------------------------- inventory
def inventory():
    org = graph("get", "/organization?$select=id")["value"][0]["id"]
    sps = paged("/servicePrincipals?$select=displayName,servicePrincipalType,appOwnerOrganizationId,appId&$top=999")
    apps = paged("/applications?$select=displayName,appId,passwordCredentials,keyCredentials,requiredResourceAccess&$top=999")
    own = [s for s in sps if s.get("appOwnerOrganizationId") == org]
    mi = [s for s in sps if s.get("servicePrincipalType") == "ManagedIdentity"]
    rows = []
    for a in apps:
        perms = sum(len(x.get("resourceAccess", [])) for x in a.get("requiredResourceAccess", []))
        exp = [c.get("endDateTime") for c in a.get("passwordCredentials", []) + a.get("keyCredentials", [])]
        rows.append({"app": a["displayName"], "secrets": len(a.get("passwordCredentials", [])),
                     "certificates": len(a.get("keyCredentials", [])), "api_permissions": perms,
                     "credential_expiry": min(exp) if exp else None})
    return org, {"service_principals": len(sps), "own": len(own), "managed_identities": [m["displayName"] for m in mi],
                 "microsoft_and_third_party": len(sps) - len(own) - len(mi), "app_registrations": rows}


def print_inventory(inv):
    print(f"  service principals: {inv['service_principals']} = {inv['own']} HVMC-created + "
          f"{len(inv['managed_identities'])} managed identities + {inv['microsoft_and_third_party']} Microsoft/third-party")
    with_creds = [r for r in inv["app_registrations"] if r["secrets"] or r["certificates"]]
    print(f"  app registrations: {len(inv['app_registrations'])}; with credentials: {len(with_creds)}; "
          f"with API permissions: {sum(1 for r in inv['app_registrations'] if r['api_permissions'])}")
    for r in with_creds:
        print(f"    {r['app']:36} secrets={r['secrets']} certs={r['certificates']} expires={r['credential_expiry']}")


# ---------------------------------------------------------------- certificate from the HVMC PKI
def issue_certificate():
    """RSA-2048 key + certificate signed by HVMC Issuing CA 1 (rubric 4 PKI), clientAuth, 365 days."""
    sys.path.insert(0, REPO_PKI)
    import key_management as km
    store = km.KeyStore(os.path.join(REPO_PKI, "pki"), km.get_passphrase(os.path.join(REPO_PKI, "pki", "private")))
    ca_key = store.private("hvmc-issuing-ca-1")
    ca_cert = x509.load_pem_x509_certificate(open(os.path.join(REPO_PKI, "pki", "certs", "hvmc-issuing-ca-1.crt.pem"), "rb").read())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Horizon Valley Medical Center"),
                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Workload Identities"),
                         x509.NameAttribute(NameOID.COMMON_NAME, "HVMC Lab Results Sync (NHI)")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    os.makedirs(SECRETS, mode=0o700, exist_ok=True)
    kp = os.path.join(SECRETS, "hvmc-lab-results-sync.key.pem")
    fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(os.path.join(SECRETS, "hvmc-lab-results-sync.crt.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def load_certificate():
    key = serialization.load_pem_private_key(open(os.path.join(SECRETS, "hvmc-lab-results-sync.key.pem"), "rb").read(), None)
    cert = x509.load_pem_x509_certificate(open(os.path.join(SECRETS, "hvmc-lab-results-sync.crt.pem"), "rb").read())
    return key, cert


# ---------------------------------------------------------------- create, consent
def find_app():
    a = graph("get", f"/applications?$filter=displayName eq '{APP_NAME}'&$select=id,appId,keyCredentials")["value"]
    return a[0] if a else None


def create(tenant):
    key, cert = issue_certificate()
    der = cert.public_bytes(serialization.Encoding.DER)
    me = graph("get", "/me?$select=id")["id"]
    app = graph("post", "/applications", {
        "displayName": APP_NAME, "signInAudience": "AzureADMyOrg",
        "notes": f"{TICKET}. Non-human identity: reads members of the laboratory groups for the lab results interface. "
                 "Owner: IAM administrator. Credential: certificate from HVMC Issuing CA 1, no secrets. Review quarterly.",
        "tags": ["HVMC-NHI", "workload-identity", TICKET],
        "keyCredentials": [{"type": "AsymmetricX509Cert", "usage": "Verify", "key": base64.b64encode(der).decode(),
                            "displayName": "CN=HVMC Lab Results Sync (NHI) - HVMC Issuing CA 1"}],
        "requiredResourceAccess": [{"resourceAppId": GRAPH_APP_ID,
                                    "resourceAccess": [{"id": GROUP_MEMBER_READ_ALL, "type": "Role"}]}],
    })
    graph("post", f"/applications/{app['id']}/owners/$ref", {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{me}"})
    sp = graph("post", "/servicePrincipals", {"appId": app["appId"], "tags": ["HVMC-NHI", "WindowsAzureActiveDirectoryIntegratedApp"],
                                              "notes": f"{TICKET} - see app registration notes"})
    graph("post", f"/servicePrincipals/{sp['id']}/owners/$ref", {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{me}"})
    graph_sp = graph("get", f"/servicePrincipals?$filter=appId eq '{GRAPH_APP_ID}'&$select=id")["value"][0]
    graph("post", f"/servicePrincipals/{sp['id']}/appRoleAssignments",
          {"principalId": sp["id"], "resourceId": graph_sp["id"], "appRoleId": GROUP_MEMBER_READ_ALL})
    print(f"  created app registration + service principal '{APP_NAME}' (single tenant), owner = IAM administrator")
    print("  credential: certificate (no secret); private key in secrets/ (0600, git-ignored)")
    print("  admin consent granted: Microsoft Graph GroupMember.Read.All (application) - nothing else")
    return app, sp, cert


# ---------------------------------------------------------------- the NHI signs in with its certificate
def token(tenant, client_id, key, cert):
    """OAuth 2.0 client credentials with a signed JWT client assertion (RFC 7523) - what MSAL does internally."""
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t": b64u(cert.fingerprint(hashes.SHA1()))}
    claims = {"aud": url, "iss": client_id, "sub": client_id, "jti": str(uuid.uuid4()), "nbf": now, "iat": now, "exp": now + 600}
    signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}".encode()
    assertion = signing_input.decode() + "." + b64u(key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()))
    body = urllib.parse.urlencode({"client_id": client_id, "scope": "https://graph.microsoft.com/.default",
                                   "grant_type": "client_credentials", "client_assertion": assertion,
                                   "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, body)) as r:
        return json.load(r)["access_token"]


def call(tok, method, path, body=None):
    req = urllib.request.Request("https://graph.microsoft.com/v1.0" + path, method=method,
                                 data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r) if r.status != 204 else {}
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test(tenant):
    app = find_app()
    key, cert = load_certificate()
    lab = graph("get", f"/groups?$filter=displayName eq '{LAB_GROUP}'&$select=id")["value"][0]["id"]
    for attempt in range(12):          # new permissions can take a minute to reach the token service
        tok = token(tenant, app["appId"], key, cert)
        claims = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
        if "GroupMember.Read.All" in claims.get("roles", []):
            break
        time.sleep(10)
    print(f"  signed in as the NHI with its certificate: token issued; roles in token = {claims.get('roles')}; "
          f"identity type = {'application' if claims.get('idtyp') == 'app' else claims.get('idtyp')}")
    results = []
    for label, method, path, body, expect in [
            (f"read members of {LAB_GROUP}", "GET", f"/groups/{lab}/members?$select=displayName", None, 200),
            ("list all users in the directory", "GET", "/users?$select=displayName&$top=5", None, 403),
            (f"change the description of {LAB_GROUP}", "PATCH", f"/groups/{lab}", {"description": "changed by NHI"}, 403)]:
        status, data = call(tok, method, path, body)
        ok = status == expect
        detail = f"{len(data.get('value', []))} members" if status == 200 else data.get("error", {}).get("code", "")
        print(f"    {'PASS' if ok else 'FAIL'}  {label:42} -> HTTP {status} {detail} (expected {expect})")
        results.append({"test": label, "expected": expect, "status": status, "pass": ok, "detail": detail})
    save("nhi_test", {"roles_in_token": claims.get("roles"), "results": results})
    return all(r["pass"] for r in results), results, cert


def write_register(cert, results):
    reg = [{
        "nhi": APP_NAME, "type": "Application service principal (single tenant)", "ticket": TICKET,
        "purpose": "Read members of the laboratory groups for the lab results interface",
        "owner": "IAM administrator (Sabitha S Karanavar)", "business_owner": "Laboratory lead (Daniel Osei)",
        "credential": "X.509 certificate, RSA-2048, issued by HVMC Issuing CA 1; no client secrets",
        "certificate_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "credential_expires": str(cert.not_valid_after_utc.date()), "rotate_by": str((cert.not_valid_after_utc - dt.timedelta(days=30)).date()),
        "private_key_location": "Local, mode 0600 (to move into Azure Key Vault)",
        "permissions": ["Microsoft Graph GroupMember.Read.All (application, admin consent)"],
        "verified_least_privilege": {r["test"]: r["status"] for r in results},
        "created": str(dt.date.today()), "next_review": "HVMC-AR-2027-Q1",
    }]
    with open(os.path.join(HERE, "nhi_register.json"), "w") as f:
        json.dump(reg, f, indent=2)
    print("  NHI register written: nhi_register.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--test", action="store_true")
    a = ap.parse_args()
    org, inv = inventory()
    print(f"HVMC Step 8 non-human identities - {'APPLY' if a.apply else 'TEST' if a.test else 'DRY RUN (no changes)'}")
    print("\n=== NHI inventory (read-only) ===")
    print_inventory(inv)
    if a.test:
        ok, _, _ = test(org)
        return 0 if ok else 1
    existing = find_app()
    print(f"\n=== Plan ({TICKET}) ===")
    print(f"  '{APP_NAME}': {'already exists' if existing else 'will be created'}")
    print("  certificate credential from HVMC Issuing CA 1 (365 days); no client secret")
    print("  Microsoft Graph permission: GroupMember.Read.All (application) with admin consent - nothing else")
    print(f"  then sign in as the NHI and prove: read {LAB_GROUP} members = allowed; list users = denied; change group = denied")
    if not a.apply:
        print("\n  DRY RUN: nothing created. Run with --apply")
        save("nhi_inventory_before", inv)
        return 0
    if existing:
        print("  already created - running the test only")
    else:
        create(org)
    ok, results, cert = test(org)
    write_register(cert, results)
    _, inv_after = inventory()
    save("nhi_inventory_after", inv_after)
    print("\n  RESULT:", "all least-privilege tests passed" if ok else "a test did not behave as expected")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
