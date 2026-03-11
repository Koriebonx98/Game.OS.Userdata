# TestData — Mock Directories for GameScannerService

This directory simulates a drive root for testing the `GameScannerService`.
It contains fake game executables and repack archives across all supported formats.

## Structure

```
TestData/
├── Games/
│   ├── FakeGame1/
│   │   └── FakeGame.exe                    # Windows .exe (MZ header, 64 bytes)
│   ├── FakeGame2/
│   │   └── FakeGame2.app/                  # macOS .app bundle
│   │       └── Contents/
│   │           ├── Info.plist
│   │           └── MacOS/FakeGame2         # macOS executable (chmod +x)
│   ├── FakeGame3/
│   │   └── FakeGame                        # Linux ELF binary (ELF magic, chmod +x)
│   ├── FakeGame4/
│   │   └── FakeGame4.exe                   # Windows .exe (MZ header, 64 bytes)
│   └── FakeGame5/
│       └── FakeGame5                       # Linux ELF binary (ELF magic, chmod +x)
├── Repacks/
│   ├── FakeRepack.zip                       # Fake ZIP archive (PK header)
│   ├── FakeRepack.rar                       # Fake RAR archive (Rar! header)
│   ├── FakeRepack1/
│   │   └── FakeRepack1.zip                  # Sub-folder ZIP repack
│   ├── FakeRepack2/
│   │   └── FakeRepack2.7z                   # Sub-folder 7-Zip repack (7z header)
│   ├── A-Way-Out-SteamRIP.zip               # Archive with scene suffix → normalised to "A Way Out"
│   ├── FakeGame1.zip                        # Repack for a game also in Games/ → IsInstalledGame=true
│   └── FakeGame3WithUpdate/
│       ├── setup.zip                        # Main repack archive
│       └── Update/                          # Update sub-folder → HasUpdate=true
│           └── update.zip
└── Roms/
    ├── GBA/Games/
    │   └── FakeGBAGame/FakeGBAGame.gba
    ├── PS3/Games/
    │   └── FakePS3Game/FakePS3Game.iso
    └── SNES/Games/
        ├── FakeSNESGame.snes                # No region tag
        ├── FakeSNESGame (Europe).snes       # Region tag stripped → merged into FakeSNESGame
        └── FakeSNESGame (USA).snes          # Region tag stripped → merged into FakeSNESGame
```

## Running the Detection Test

```bash
cd GameScanner.Tests
dotnet run
```

Expected output:
```
📀 Detected Games (5):
  ✅  FakeGame1   [exe]  ...
  ✅  FakeGame2   [app]  ...
  ✅  FakeGame3   [elf]  ...
  ✅  FakeGame4   [exe]  ...
  ✅  FakeGame5   [elf]  ...

📦 Detected Repacks (7):
  ✅  A Way Out             [zip]  ...   ← "A-Way-Out-SteamRIP" normalised
  ✅  FakeGame1             [zip]  ...   ← IsInstalledGame=true
  ✅  FakeGame3WithUpdate / setup.zip [zip] ...  ← HasUpdate=true
  ✅  FakeRepack            [rar]  ...
  ✅  FakeRepack            [zip]  ...
  ✅  FakeRepack1 / ...     [zip]  ...
  ✅  FakeRepack2 / ...     [7z]   ...

🕹️  Detected ROMs (3):
  ✅  [GBA]   FakeGBAGame   [gba]  ...
  ✅  [PS3]   FakePS3Game   [iso]  ...
  ✅  [SNES]  FakeSNESGame  [snes] ...  regions=[USA,Europe]  +2 more

🔧 Archive Title Normalisation:
  ✅  A-Way-Out-SteamRIP.zip → "A Way Out"

📂 Repack + Update Detection:
  ✅  FakeGame3WithUpdate has Update: .../Update

🏷️  IsInstalledGame Detection:
  ✅  FakeGame1.zip is marked IsInstalledGame=true (also in Games/)

═══════════════════════════════════════════════════════════════
  ✅  ALL CHECKS PASSED — Game detection is working correctly!
═══════════════════════════════════════════════════════════════
```

Exit code `0` = all checks passed. Exit code `1` = failure.

## Fake File Headers

| File | Magic Bytes | Scanner detects via |
|------|------------|---------------------|
| `FakeGame.exe` / `FakeGame4.exe` | `4D 5A` (MZ) | `*.exe` extension |
| `FakeGame2.app` | `.app` directory | `*.app` dir pattern |
| `FakeGame` / `FakeGame5` | `7F 45 4C 46` (ELF) + chmod +x | ELF magic + execute bit |
| `FakeRepack.zip` | `50 4B 03 04` (PK) | `.zip` extension |
| `FakeRepack.rar` | `52 61 72 21` (Rar!) | `.rar` extension |
| `FakeRepack2.7z` | `37 7A BC AF` (7z) | `.7z` extension |
