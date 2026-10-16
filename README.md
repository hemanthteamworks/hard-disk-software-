# Disk Catalog - Stage 2

Safe local catalog software for external hard disks.

## What it stores

The app stores file metadata only:

- disk ID
- file name
- relative folder path
- extension
- file size
- created date
- modified date

It does not store file contents and it does not modify files.

## Run

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Workflow

1. Put physical labels on disks: `HD01` to `HD20`.
2. Open the app and create the admin password.
3. Plug one disk into the computer.
4. Click `Scan Disk`.
5. Enter the disk ID, for example `HD01`.
6. Enter the drive path, for example `E:\`.
7. Click `Scan Disk`.
8. Repeat for each disk.

## Screens

- `Dashboard`: shows disk count, file count, cataloged size, latest scan, and top file types.
- `Scan Disk`: reads the file list and saves it to SQLite.
- Scanning uses iterative `os.scandir()` traversal and writes to SQLite staging tables in batches of 5,000 records, keeping memory stable on very large disks.
- The previous disk catalog remains searchable until the new scan completes and is replaced in one database transaction.
- Scanning runs in the background and shows live file/folder counts, current folder, elapsed time, scan speed, database speed, estimated remaining time when a previous scan exists, and a safe cancel action.
- Progress is persisted once per second. Running, completed, cancelled, failed, and interrupted scans appear in Scan History with the last folder and error.
- Generated cache/system folders `$RECYCLE.BIN`, `System Volume Information`, and `WUDownloadCache` are excluded and counted separately.
- `Search`: indexed token and trigram search supports partial names, multiple words, folder paths, prefixes, and small spelling mistakes without reading file contents.
- Search uses progressive AND filtering: every entered word must match, so adding words can only narrow the results.
- Direct file/folder name matches are ranked exact, prefix, partial, multi-keyword, then fuzzy. Containing-path matches appear only when no name matches exist.
- One result table shows an icon, disk ID, matched name, parent folder, containing path, created date, and modified date.
- Optional `Details` contains file size, extension, related files, or a folder preview.
- Folder created/modified timestamps are captured by new scans; older catalog rows show `Unknown` until that disk is rescanned.
- A folder match does not automatically list every file stored inside that folder.
- Each file result includes an expandable preview of up to 12 other files in the same disk folder.
- `Disks`: shows one row per scanned disk.
- `Delete Catalog` beside a disk requires the exact Disk ID, current password, and a session-bound confirmation. It creates a verified backup and removes only that disk's catalog/search/history records; physical disk files are never changed.
- `Scan History`: shows previous scan runs.
- `Duplicates`: shows duplicate file names only.
- `Export CSV`: exports the catalog to `exports/`.
- `Backup Catalog`: uses SQLite's native backup API, verifies database integrity, and saves the result to `backups/`.

## Files

- Database: `data/catalog.db`
- CSV exports: `exports/`
- Backups: `backups/`

## Security

This app binds to `127.0.0.1`, so it is local-only by default. Do not expose it to the internet.

Stage 2 adds:

- local password login
- HTTP-only session cookie
- password hashing with PBKDF2
- basic browser security headers
- no file delete, move, rename, format, or auto-organize actions

The catalog is sensitive because names and paths can reveal private information, even though original file contents are not stored.
