# Security Review

This report summarizes a read-only source review of the project. The review did not
perform live login attempts or test an external deployment.

## Findings

### HIGH — Manager can grant Administrator privileges

**Confidence:** 9/10  
**Location:** [UserList.cshtml.cs](./Areas/Identity/Pages/Account/UserList.cshtml.cs), lines 18, 101–122, 166–212, 319–324

The page allows both `Administrator` and `Manager` roles, while its role-editing
handlers validate requested roles against the full list of available roles. That
list includes `Administrator`, and the handlers add the selected role without
preventing a Manager from assigning it. A Manager can therefore promote their own
account or another account to Administrator.

**Impact:** A malicious or compromised Manager account can gain administrator
privileges.

**Recommendation:** Enforce role hierarchy rules on the server. Restrict which
roles a Manager may assign, and use an explicit allowlist rather than the full
database role list.

### MEDIUM — Temporary passwords are emailed over SMTP without TLS

**Confidence:** 9/10  
**Locations:** [UserList.cshtml.cs](./Areas/Identity/Pages/Account/UserList.cshtml.cs), lines 218–235; [CanaryLoginAlert.cs](./CanaryLoginAlert.cs), lines 31–33

The account-creation flow includes a generated temporary password in an email,
then connects to SMTP with `SecureSocketOptions.None`, which does not negotiate
transport encryption. The canary alert uses the same plaintext SMTP connection
pattern.

**Impact:** If the SMTP connection crosses an untrusted network, its contents may
be intercepted. This exposes temporary passwords and alert contents.

**Recommendation:** Require TLS with certificate validation for SMTP. Avoid
sending passwords by email; send a short-lived, single-use password setup or
reset link instead.

## Review limitations

These findings are based on static source inspection. Deployment-specific
controls, SMTP network boundaries, and runtime behavior were not independently
verified. No additional concerns with sufficient evidence were identified.
