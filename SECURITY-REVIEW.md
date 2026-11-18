# Security Review

This review combined source inspection with limited, non-destructive checks
against the local application. No external accounts were accessed, no login
guessing was performed, and no SMTP messages were sent or intercepted.

## Findings

### HIGH — Manager can grant Administrator privileges

**Confidence:** 10/10  
**Location:** [UserList.cshtml.cs](./Areas/Identity/Pages/Account/UserList.cshtml.cs), lines 18, 101–123, 172–192, 317–322

The page authorizes both `Administrator` and `Manager`, while its role mutation
handlers validate a requested role only by checking whether it exists. The
available-role list includes all roles, and the handlers do not prevent a
Manager from assigning `Administrator` to themselves or another user.

**Impact:** A malicious or compromised Manager account can gain administrator
privileges.

**Runtime verification:** An unauthenticated local request to
`/Identity/Account/UserList` redirected to login, confirming the page is
protected. The role escalation itself was not exercised: the active database
had no Manager account, and no account credentials were used.

**Recommendation:** Restrict privileged role assignment and removal on the
server. Only Administrators should be allowed to manage privileged roles; do
not rely on the role choices rendered by the page.

### HIGH — Temporary passwords are emailed over SMTP without TLS

**Confidence:** 10/10  
**Locations:** [UserList.cshtml.cs](./Areas/Identity/Pages/Account/UserList.cshtml.cs), lines 231–235; [CanaryLoginAlert.cs](./CanaryLoginAlert.cs), lines 32–33

The account-creation flow includes a generated temporary password in an email,
then connects to SMTP with `SecureSocketOptions.None`, which does not negotiate
transport encryption. The canary alert uses the same unencrypted SMTP
connection pattern. Development configuration points to a local SMTP service
on port 1025.

**Impact:** If the SMTP connection crosses an untrusted network, its contents
may be intercepted, exposing temporary passwords and alert contents.

**Runtime verification:** Source confirms the transport configuration and
password-in-email behavior. SMTP traffic was not intercepted, and no email was
sent.

**Recommendation:** Require TLS with certificate validation for SMTP. Avoid
sending passwords by email; use a short-lived, single-use password setup or
reset link instead.

## Review limitations

The audit was limited to the project source and safe local behavior. It did not
test deployment-specific controls, intercept network traffic, or exercise
privileged actions with real credentials. No additional vulnerabilities were
confirmed.
