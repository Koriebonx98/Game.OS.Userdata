Copy all *.Games.json files to the root of Koriebonx98/Games.Database.
GameBoy.Games.json and GameBoy Advance.Games.json already exist there with real games:
do NOT overwrite them - instead add the "Test" entry as the first item of their "Games" array.
Add games later via the admin tools (they write {Platform}.Games.json, with per-game data under
Data/<folder>/Games/<TitleID>/ - folder names are mapped in script.js / backend/index.js).
