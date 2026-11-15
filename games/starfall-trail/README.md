# Starfall Trail

Imported from `Koriebonx98/Starfall-trail---Game-OS` at
`baed57715aa6d32df2ac47dd3947effdf6685550`.

Launch from the Game OS store, sign in, and claim the game for free. The same
build runs on the website and in the Windows desktop shell. Keyboard,
controller, and touch controls are supported; use the fullscreen button to
expand the game.

Progress is saved at level transitions, on pause and on quit. Continue resumes
at the beginning of the saved level, not at an in-level checkpoint. Four
achievements and playtime sync through the Game OS bridge.

For two-player co-op, host a public room or invite a Game OS friend, and keep
the game open. Guests can join a public room or accept an invite. The host
simulates the shared world; either player can collect items, fight enemies and
reach the goal. The host controls pause and both players share lives.

Standalone `index.html` also supports local play, but account features and
online rooms require the Game OS launch page. The Windows installer workflow
publishes `StarfallTrail-Setup.exe` to the `starfall-trail-desktop` release on
main; the launcher downloads it from that release.
