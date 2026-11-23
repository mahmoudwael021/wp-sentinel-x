# WP Sentinel X v0.5.0 — advanced scanner development build

## Changes
- WordPress Core checksum verification for eligible PHP files using WordPress's official checksum service.
- WordPress.org plugin checksum comparison when published for the detected plugin version; missing checksums are **not** treated as clean.
- Added heuristic detections for request-controlled PHP inclusion/evaluation and combined obfuscation/remote-code patterns.
- A verified official checksum suppresses heuristic false positives for that file.
- Displays the number of officially verified PHP files in the scan progress.
- Read-only scan. No automatic deletion, repair or quarantine is triggered by full-site scan.

## Limitations / important warnings
- This is a development build, NOT independently audited or production certified. A full-site scan cannot prove a site is malware-free.
- Official checksums are not generally available for premium plugins (including Slider Revolution) or custom themes; they remain unverified.
- Core checksum mismatches can be caused by legitimate customizations; review before repair.
- Content scans cover PHP files up to 2 MiB; checksum verification may cover PHP files up to 8 MiB. Other files and the database are not malware-content-scanned.
- Checksums require outbound HTTPS to WordPress.org; network failures reduce verification coverage.
- Scan processes a limited number of files per request. Hosting performance and integration with Wordfence still need testing.
- Site root is determined by ABSPATH, not necessarily the hosting account's entire public_html if WordPress is installed in a subdirectory.
- File count does not equal number of verified files. Premium plugin checksums must be supplied separately from a trusted vendor source.
- Keep Wordfence enabled and leave auto-repair and quarantine disabled. Make a backup before installing this development version.


## v0.5.3 — Encoded payload detection
- Read-only detection of PHP disguised as `.txt` and selected other extensions (including root-level text files).
- Identifies hex2bin + eval chains and inspects bounded hex literals without executing them.
- Flags decoded remote-content/SEO cloaking indicators; does not contact remote servers.
- Maximum inspected file size remains 8 MB. No deletion or auto-quarantine.
- This is a targeted detection improvement, not a guarantee of complete malware coverage.

## v0.5.4: manual evidence-preserving quarantine
Full Site Scan offers a manual quarantine button ONLY for high-severity `encoded_payload` findings in a standalone document-root file. The operation requires administrator permissions, a nonce, an unchanged SHA-256 hash, a fresh signature recheck, and a private directory outside the WordPress document root. It copies evidence before removing the original and refuses to remove anything if safe preservation fails. It does not automatically repair modified core/plugin/theme files, and it does not quarantine other heuristic findings. Test on staging and keep independent backups.

## v0.5.5 — Quarantine Manager and SEO tampering
Shows the actual evidence path, saved quarantine records, SHA-256 integrity status, and an explicit manual restore action that never overwrites an existing file. New correlated SEO tampering detection for root PHP that writes both robots.txt and Google verification files, with manual quarantine for confirmed patterns. Lists root Google verification files for ownership review (no automatic deletion). Old v0.5.4 quarantines are not retroactively indexed; inspect the displayed evidence directory. No unattended deletion or repair.


## v0.5.6 File Protection
New File Protection submenu: root index.php SHA-256 baseline + hourly change alerts, optional chmod 444/644 (not immutable), opt-in Apache/LiteSpeed .htaccess PHP execution guards for uploads and existing writable directories. Existing .htaccess rules are preserved with backup. Nginx requires server-side configuration. Do not approve a baseline without checking file integrity. Core repair remains manual and verified. No automatic deletion of unverified files.

## v0.5.7 Auto Recovery (opt-in, development)
- New Auto Recovery admin page with explicit enablement and two independent controls.
- Root-only high-confidence encoded/SEO script quarantine, verified evidence outside document root, SHA-256, activity log.
- Root index.php repair ONLY when a built-in candidate exactly matches WordPress.org official MD5 for the installed version/locale. If it does not match, no replacement is attempted.
- No auto repair of arbitrary plugin/theme/custom files. WP-Cron is traffic dependent.
- IMPORTANT: test in staging, keep offsite backups, verify server-side PHP execution restrictions.

## v0.5.8 — cron observability and conservative locking
- Every recovery invocation records a summary in the Activity Log, including clean runs and disabled runs.
- Last execution time, counts, and status displayed in Auto Recovery.
- Uses a database option lock with a stale-lock timeout instead of a transient check/set race.
- Existing detection and quarantine policy unchanged. No claim of comprehensive malware protection.
- Verify on your live test site with a recoverable backup before enabling destructive actions.

## v0.5.9 — Read-only site monitoring
Adds daily/manual bounded PHP file inventory of uploads, plugins, themes, and mu-plugins. Baseline only on complete initial scan; subsequent changes are reported, never auto-quarantined. This is not malware certification.

## v0.6.0 — Experimental unknown-core webshell quarantine
- Adds a separate OFF-by-default option under Auto Recovery for suspicious non-distribution PHP files inside `wp-includes`.
- Requires an available official WordPress core checksum manifest and multiple file-manager/webshell behavior signals. Never automatically removes paths in the official manifest.
- Preserves verified SHA-256 evidence outside the document root before removal, logs action, and bounds traversal.
- IMPORTANT: heuristic detection can still generate false positives; review unknown files and back up the site first. No live WordPress integration tests were performed for this release.

## v0.6.1 — Auto Recovery log usability
- 25 records per page, filterable by action/error, pagination over the existing bounded 200-entry option.
- Suppresses repetitive healthy no-action cron logs to one daily heartbeat; last-run summary still updates every run.
- Existing events and security settings are preserved on upgrade.
- This is a development build. It does not provide database-level pagination or permanent incident archives.

## v0.6.3 — Persistence Monitoring (experimental)
- Adds a read-only 15-minute WP-Cron hook (`wpsx_persistence_monitor_15m`) for sensitive configuration files, mu-plugins, executable files in uploads/upgrade, administrator account identities, selected WordPress options, and WP-Cron hook names.
- First baseline is observational and **not** a clean bill of health. Baseline does not automatically change after detected modifications. An administrator may explicitly approve a replacement snapshot after investigation.
- Change alerts are logged and use existing critical-email notifications; events capped at 250. Checks have bounded inventories; an incomplete scan is never accepted as a baseline.
- Does not remove files, prevent attacker writes, inspect server cron, inspect all database records, or identify the writer of a file. WP-Cron requires an actual server cron for reliable scheduling.

## v0.6.3 — Resumable persistence inventory
- Traverses uploads, upgrade and mu-plugins in batches of at most 1,800 directory entries per invocation, using a persisted queue and per-directory offsets.
- Only records executable PHP-like files in uploads/upgrade; mu-plugins remain fully monitored.
- Partial scans never become a baseline and never generate misleading zero-change comparisons.
- Shows traversed entries and pending directories in Persistence Monitoring.
- Filesystem inventory is read-only. This does not prove a site is clean; changes made during a multi-run inventory can require additional investigation.

## 0.6.4 — Automatic Self-Test
Adds a daily read-only health-check page under Sentinel X. Checks scheduled recovery and persistence hooks, enabled recovery, evidence directory availability, a safe temporary .txt SHA-256 write/verify/delete roundtrip, and completed persistence inventory. The test does not create executable files or exercise real malware quarantine. Existing conservative Auto Recovery remains unchanged. A failed check triggers an admin-email attempt through existing critical-event notifications; delivery depends on WordPress mail configuration. A clean result does not prove a site is secure.


## v0.6.5 Critical file integrity and Self-Test
- Added 15-minute SHA-256 checks for wp-config.php (including parent placement), .htaccess, .user.ini, index.php, WordPress bootstrap and selected wp-content drop-ins.
- Initial fingerprints are observational and untrusted. No automatic restore, chmod, or baseline approval is performed.
- Self-Test distinguishes in-progress inventory from failed inventory when a recent completed scan exists.
- Requires manual review of any critical file changes and real server-level protection for strong enforcement.

### v0.6.6 — packed loader detection
Root auto-recovery now recognizes correlated encoded PHP loaders that use a
base64-encoded decompression function name, a long packed payload, and dynamic
`eval`. This covers the supplied `events.php` / `stores.php` specimens without
executing them. Auto-quarantine still requires both `enabled` and `quarantine`
settings, a writable standalone root file, and verified private evidence.
This is a targeted detection update, not a guarantee of malware-free hosting.

### v0.6.11 — nested MU loader detection
- Recognizes oversized nested `eval(base64_decode(...))` must-use plugin loaders without requiring a visible decompression call.
- Preserves evidence and quarantines through existing opt-in Auto Recovery workflow.
- Static analysis only; no malicious payload evaluation.
- Still requires WordPress to boot and cron to run; does not identify the reinfection source.
