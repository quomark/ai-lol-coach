# AI LoL Coach

## Project Goal
Build an AI coach that reads the USER'S OWN .rofl replay files and provides coaching feedback. The user must be able to upload their own replay and get analysis.

## Critical Constraint
**Maknee's HuggingFace dataset is NOT acceptable as the data source.** The product requires reading arbitrary user replays, not pre-decoded community datasets. We MUST solve replay decryption — either:
1. Crack the encrypted packet format (reverse-engineer varint reader + field ciphers end-to-end)
2. Get an initialized binary dump (bypass Vanguard / VM approach / runtime dump)
3. Any other method that decodes .rofl files from the current patch

Do NOT suggest falling back to the dataset as a replacement for replay decoding.

## Key Technical Context
- Cipher decode module at `ml/emulator/cipher_decode.py` has all 17 field ciphers + inverse tables (working, verified)
- The emulator approach is partially working but the deserializer returns AL=0 for all packets
- See `.claude/projects/.../memory/emulator-findings.md` for full details of all approaches tried
