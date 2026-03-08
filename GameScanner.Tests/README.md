# GameScanner.Tests — Game Detection Verification

A lightweight console application that proves the `GameScannerService` correctly detects all supported game and repack formats using the fake test data in `../TestData/`.

## What it tests

| Format | Fake file | Expected type |
|--------|-----------|--------------|
| Windows `.exe` | `FakeGame1/FakeGame.exe` | `exe` |
| macOS `.app` bundle | `FakeGame2/FakeGame2.app` | `app` |
| Linux ELF binary | `FakeGame3/FakeGame` (chmod +x) | `elf` |
| Windows `.exe` | `FakeGame4/FakeGame4.exe` | `exe` |
| Linux ELF binary | `FakeGame5/FakeGame5` (chmod +x) | `elf` |
| ZIP archive | `Repacks/FakeRepack.zip` | `zip` |
| RAR archive | `Repacks/FakeRepack.rar` | `rar` |
| Sub-folder ZIP | `Repacks/FakeRepack1/FakeRepack1.zip` | `zip` |
| Sub-folder 7z | `Repacks/FakeRepack2/FakeRepack2.7z` | `7z` |

## How to run

```bash
cd GameScanner.Tests
dotnet run
```

## Expected output

```
═══════════════════════════════════════════════════════════════
  Game.OS — GameScannerService Detection Test
═══════════════════════════════════════════════════════════════
  Scanning TestData root: .../TestData

📀 Detected Games (5):
───────────────────────────────────────────────────────────────
  ✅  FakeGame1             [exe]  ...
  ✅  FakeGame2             [app]  ...
  ✅  FakeGame3             [elf]  ...
  ✅  FakeGame4             [exe]  ...
  ✅  FakeGame5             [elf]  ...

📦 Detected Repacks (4):
───────────────────────────────────────────────────────────────
  ✅  FakeRepack                     [rar]  7 B
  ✅  FakeRepack                     [zip]  10 B
  ✅  FakeRepack1 / FakeRepack1.zip  [zip]  3 B
  ✅  FakeRepack2 / FakeRepack2.7z   [7z]   8 B

═══════════════════════════════════════════════════════════════
  ✅  ALL CHECKS PASSED — Game detection is working correctly!
═══════════════════════════════════════════════════════════════
```

Exit code `0` = all checks passed. Exit code `1` = failure.
