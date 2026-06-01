# Digital Forensics Investigation — SCHARDT Case

Forensic analysis of a real-world hacking case from the NIST CFReDS 
reference dataset using The Sleuth Kit (TSK) on Kali Linux.

## Case Summary
Investigated a disk image seized from a suspect (Greg Schardt / "Mr. Evil") 
accused of parking near Wi-Fi hotspots to intercept traffic and steal 
credentials from victims.

## Tools & Technologies
- The Sleuth Kit (TSK) v4.x
- Kali Linux
- md5sum / sha256sum
- mactime / strings / xxd / dd

## What was done
- Verified integrity of 4.6 GB disk image (8 parts) via MD5 and SHA-256
- Mapped NTFS partition table and extracted file system metadata
- Identified 10 hacking tools installed on the suspect's machine
- Recovered deleted files using icat -r and carved 2 JPEG images from unallocated space
- Extracted slack space from NETLOG.TXT
- Reconstructed a criminal activity timeline of 50,499 events (Aug 20–27, 2004)

## Key Evidence Found
- irunin.ini tied Greg Schardt = Mr. Evil = Administrator
- interception (173 KB PCAP) proved active MSN Hotmail session interception
- 6 dedicated hacking tools: Cain, Ethereal, Network Stumbler, 123WASP, mIRC, WinPcap
- Email: whoknowsme@sbcglobal.net confirmed in NTUSER.DAT registry

## Score
100 / 100 + 5 bonus points (full marks on all 7 phases)
