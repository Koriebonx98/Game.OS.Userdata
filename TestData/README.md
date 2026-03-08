# TestData — Mock Directories for GameScannerService

This directory simulates a drive root for testing the `GameScannerService`.

## Structure

```
TestData/
├── Games/
│   ├── FakeGame1/
│   │   └── FakeGame.exe          # Windows executable (MZ header)
│   ├── FakeGame2/
│   │   └── FakeGame.app/         # macOS .app bundle
│   │       └── Contents/MacOS/
│   └── FakeGame3/
│       └── FakeGame              # Linux ELF binary (ELF magic, chmod +x)
└── Repacks/
    ├── FakeRepack.zip            # Fake ZIP archive
    ├── FakeRepack.rar            # Fake RAR archive
    └── FakeRepack1/
        └── FakeRepack1.zip       # Sub-folder repack
```

## Usage

Point `GameScannerService` at `TestData/` as a drive root during testing.
The scanner will detect:
- **Detected on Drive**: FakeGame1, FakeGame2, FakeGame3
- **Ready to Install**: FakeRepack.zip, FakeRepack.rar, FakeRepack1/FakeRepack1.zip
