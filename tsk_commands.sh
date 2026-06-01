#!/bin/bash
# ============================================================
# SCHARDT Forensic Investigation — TSK Command Reference
# Case: SCHARDT Hacking Case (NIST CFReDS)
# Investigator: Abdallah Mohamed Ramadan Hussein
# Tools: The Sleuth Kit (TSK) v4.x on Kali Linux
# Partition Offset: 63 sectors (used as -o flag throughout)
# ============================================================

# ── PHASE 1: Image Acquisition & Integrity ──────────────────

# Download image parts with retry
curl --retry 5 -O https://cfreds-archive.nist.gov/images/hacking-dd/SCHARDT.00{1..8}

# Verify MD5 hashes for each part
md5sum SCHARDT.001 SCHARDT.002 SCHARDT.003 SCHARDT.004
md5sum SCHARDT.005 SCHARDT.006 SCHARDT.007 SCHARDT.008

# Combine parts into single image
cat SCHARDT.00{1..8} > SCHARDT.img

# Verify combined image SHA-256
sha256sum SCHARDT.img

# Write-protect the image (preserve evidence integrity)
chmod 444 SCHARDT.img


# ── PHASE 2: Partition & File System Analysis ────────────────

# List partition table
mmls SCHARDT.img

# File system details (offset = 63 sectors)
fsstat -o 63 SCHARDT.img


# ── PHASE 3: File Name Layer Analysis ───────────────────────

# Root directory listing
fls -o 63 SCHARDT.img

# Navigate specific directory by inode
fls -o 63 SCHARDT.img 344        # Mr. Evil's profile (inode 344)
fls -o 63 SCHARDT.img 8394       # Desktop directory
fls -o 63 SCHARDT.img 7356       # My Documents

# List deleted files at root
fls -o 63 -d SCHARDT.img

# List deleted files recursively in Mr. Evil's profile
fls -o 63 -d -r SCHARDT.img 344

# Generate mactime body file (all file timestamps)
fls -o 63 -r -m '/' SCHARDT.img > body.txt


# ── PHASE 4: Metadata Layer Analysis ────────────────────────

# inode metadata — irunin.ini (smoking gun: ties Schardt = Mr. Evil)
istat -o 63 SCHARDT.img 11776

# inode metadata — NTUSER.DAT (Mr. Evil's registry hive)
istat -o 63 SCHARDT.img 345

# inode metadata — interception PCAP file
istat -o 63 SCHARDT.img 12264

# List unallocated (deleted) inodes
ils -o 63 -A SCHARDT.img


# ── PHASE 5: Data Unit Layer & File Recovery ────────────────

# Extract irunin.ini contents
icat -o 63 SCHARDT.img 11776

# Recover deleted wizdata.dat
icat -o 63 -r SCHARDT.img 10091 > recovered_wizdata.dat

# Recover deleted yahoo cache (GIF image)
icat -o 63 -r SCHARDT.img 11156 > recovered_yahoo.gif

# Verify interception PCAP magic bytes (D4 C3 B2 A1 = Wireshark)
icat -o 63 SCHARDT.img 12264 | xxd | head -5

# Extract 2.9 GB unallocated space
blkls -o 63 SCHARDT.img > unallocated.dd

# Find JPEG signatures in unallocated space (2 hits found)
sigfind "FFD8FF" unallocated.dd

# Carve first JPEG image (block 335375)
dd if=unallocated.dd bs=512 skip=335375 count=200 > carved_jpeg1.jpg


# ── PHASE 6: Slack Space Analysis ───────────────────────────

# View NETLOG.TXT with slack space (inode 125)
icat -o 63 -s SCHARDT.img 125 | xxd


# ── PHASE 7: Application Layer & Artifacts ──────────────────

# Extract registry hives
icat -o 63 SCHARDT.img 9742 > software.hive     # SOFTWARE hive
icat -o 63 SCHARDT.img 345  > ntuser.hive        # NTUSER.DAT (Mr. Evil)
icat -o 63 SCHARDT.img 336  > system.hive        # SYSTEM hive

# Find email settings in NTUSER.DAT
strings -e l ntuser.hive | grep smtp
strings -e l ntuser.hive | grep whoknowsme

# Find Mr. Evil's email address in full image
strings -o -t d SCHARDT.img | grep whoknowsme

# Find timezone setting
strings system.hive | grep central


# ── BONUS: mactime Timeline ──────────────────────────────────

# Generate 50,499-event chronological timeline
mactime -b body.txt -d > timeline.csv

# Filter timeline for hacking tool activity
grep -i "ethereal\|cain\|stumbler\|interception\|irunin" timeline.csv
