using System;
using System.Linq;
using System.Threading.Tasks;
using GameLauncher.ViewModels;

class Program
{
    static async Task<int> Main()
    {
        foreach (var theme in new[] { "PS5", "PS6", "GameOS", "Switch", "SteamBPM", "XBOne", "Wii" })
        {
            var vm = new QuickMenuViewModel
            {
                QuickMenuTheme = theme,
                CurrentGameTitle = "Ghosts",
                CurrentGamePlatform = "PC",
                IsPlayingGame = true,
            };
            for (int i = 1; i <= 7; i++)
                vm.Friends.Add(new FriendPresenceVm { Username = $"friend{i}" });

            string? invited = null, game = null, connection = null;
            vm.OnInviteFriend = (friend, title, platform, method) =>
            {
                invited = friend;
                game = title;
                connection = method;
                return Task.FromResult(true);
            };

            if (theme == "Wii")
            {
                vm.HubActions.Single(a => a.Title == "Friends").Run!();
                Check(vm.IsFriendsPage, "Wii friends action opens the invite list");
            }
            else vm.ActivePage = "friends";

            var action = vm.HubActions.Single(a => a.Title == "Invite friend7");
            vm.HubActionIndex = vm.HubActions.IndexOf(action);
            action.Run!();
            Check(invited == "friend7" && game == "Ghosts" && connection == "Game.OS room",
                $"{theme} invites every friend through the room handler");
            Check(vm.InviteStatusMessage.Contains("Invite sent") &&
                  vm.HubActions[vm.HubActionIndex].Title == "Invite friend7",
                $"{theme} shows the result without losing the selection");

            vm.IsPlayingGame = false;
            vm.CurrentGameTitle = "";
            invited = null;
            await vm.InviteFriendCommand.ExecuteAsync("friend7");
            Check(invited == null && vm.InviteStatusMessage.Contains("Start a game"),
                $"{theme} does not send an invite without a game");

            vm.CurrentGameTitle = "Ghosts";
            vm.IsPlayingGame = true;
            vm.OnInviteFriend = (_, _, _, _) => throw new InvalidOperationException("Room unavailable");
            await vm.InviteFriendCommand.ExecuteAsync("friend7");
            Check(vm.InviteStatusMessage.Contains("Room unavailable") &&
                  vm.HubActions[vm.HubActionIndex].Title == "Invite friend7",
                $"{theme} shows room errors without losing the selection");
        }

        var xbox = new QuickMenuViewModel
        {
            QuickMenuTheme = "XB360", CurrentGameTitle = "Ghosts", CurrentGamePlatform = "PC",
            IsPlayingGame = true, Xb360FriendsSubMode = true,
        };
        xbox.Friends.Add(new FriendPresenceVm { Username = "friend" });
        string? recipient = null;
        xbox.OnInviteFriend = (friend, _, _, method) =>
        {
            recipient = method == "Game.OS room" ? friend : null;
            return Task.FromResult(true);
        };
        xbox.ActivateXb360FriendItem();
        xbox.MoveXb360FriendSelection(1);
        xbox.ActivateXb360FriendItem();
        Check(recipient == "friend", "Xbox 360 controller invite uses the room handler");
        return 0;
    }

    static void Check(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException(description);
        Console.WriteLine("PASS " + description);
    }
}
