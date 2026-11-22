# SecureVault

SecureVault is a local PySide6 application for AES-256-GCM encrypted backups,
integrity-checked restores, and recovery requiring two separate custodians.

## Run

Install the packages in `requirements.txt`, then start the application:

```powershell
python -m pip install -r requirements.txt
python main.py
```

On a new database, choose **Administrator Sign In** to create the first
Administrator account.
Existing accounts are retained with their assigned roles when the database is
upgraded. Public signup is disabled after initial setup; the Administrator
creates one account for Custodian A and one for Custodian B from **Custodians**.
Roles are assigned to accounts and are not selected at login. Custodians must
replace their temporary passwords at first sign-in. The welcome screen provides
separate **Administrator Sign In** and **Custodian Sign In** entry points, and
each sign-in option accepts only accounts with its matching role.

Each custodian signs in and sets a private recovery passphrase of at least 12
characters in **Verify Share**. This is separate from the login password.
SecureVault automatically generates the custodian's RSA key pair during this
one-time enrollment and stores the public key plus a passphrase-encrypted
private key. The Administrator never receives the private key or the recovery
passphrase. Enrollment must be completed before creating protected backups.
The passphrase cannot be reset by the Administrator; losing it means that
custodian cannot unlock their shares.

The Administrator creates backups with a name, source folder, and encrypted
archive location. SecureVault splits the archive key, encrypts each share for
its assigned custodian, and stores only the encrypted envelopes with the backup
record. The Administrator interface receives only the encrypted envelopes;
plaintext shares are not displayed or written as files. Each envelope is bound
to the custodian, role, and archive digest, so shares cannot be substituted
across backups. Custodians see their assigned backup/share entries appear
automatically in **Verify Share**. **My Backups** shows cataloged backups;
**Verify Backup** checks the archive digest.

To restore, the Administrator selects a cataloged backup and requests recovery.
The request is automatically assigned to the two custodians recorded for that
backup. Each custodian signs in separately, reviews the request, enters their
own recovery passphrase, and approves or rejects. A wrong passphrase is denied
and recorded without logging secret material. The Administrator cannot access
custodian pages or approve on their behalf. After both custodians approve,
SecureVault keeps their decrypted shares only in the running application's
memory and enables restore. Restarting the app resets outstanding approvals;
both custodians must approve again. During restore, the app authenticates the
archive and verifies each recovered file against its SHA-256 manifest before
writing files.

The archive uses SecureVault's authenticated binary format, not a ZIP file.
Older catalog entries without custodian-encrypted shares cannot be restored
through this two-custodian flow and must be recreated as protected backups.
Standalone CLI share-file backup/restore is disabled so it cannot bypass
custodian approval.

The Administrator can review **Audit Logs**, **Security Alerts**, and custodian
account status. Custodians see their **Pending Requests**, **Verify Share**, and
**Approval History**. Audit entries do not contain passwords, encryption keys,
or share contents.

Login passwords are stored as salted PBKDF2 hashes. Custodian shares are
encrypted with RSA-OAEP/SHA-256 and bound to the assigned custodian, role, and
archive digest. Recovery shares are not persisted in the database after
approval. Python and the operating system cannot guarantee erasure of
immutable secrets from process memory, so the app clears mutable share buffers
on a best-effort basis after restore. The archive digest verifies the encrypted
file as stored; per-file integrity is verified during restore. Use synthetic
files in an isolated lab environment.
