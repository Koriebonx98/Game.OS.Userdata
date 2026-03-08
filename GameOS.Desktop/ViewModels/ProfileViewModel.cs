using CommunityToolkit.Mvvm.ComponentModel;
using GameOS.Desktop.Models;
using GameOS.Desktop.Services;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace GameOS.Desktop.ViewModels;

public class PlatformGroupViewModel
{
    public string Platform { get; set; } = "";
    public List<Game> Games { get; set; } = new();
    public int Count => Games.Count;
}

public partial class ProfileViewModel : ViewModelBase
{
    private readonly string _targetUsername;

    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _email = "";
    [ObservableProperty] private string _memberSince = "";
    [ObservableProperty] private string _initials = "";
    [ObservableProperty] private int _totalGames;
    [ObservableProperty] private int _wishlistCount;
    [ObservableProperty] private int _platformCount;
    [ObservableProperty] private System.Collections.ObjectModel.ObservableCollection<PlatformGroupViewModel> _gamesByPlatform = new();
    [ObservableProperty] private bool _isLoading = true;
    [ObservableProperty] private string _errorMessage = "";

    public ProfileViewModel(string username)
    {
        _targetUsername = username;
        Username = username;
        Initials = GetInitials(username);
    }

    private static string GetInitials(string name) =>
        name.Length > 0 ? name[..System.Math.Min(2, name.Length)].ToUpperInvariant() : "?";

    public async Task LoadAsync()
    {
        IsLoading = true;
        try
        {
            var user = await AuthService.GetUserAsync(_targetUsername);
            if (user == null)
            {
                ErrorMessage = $"User '{_targetUsername}' not found.";
                return;
            }
            Username = user.Username;
            Email = user.Email;
            MemberSince = user.CreatedAt;
            Initials = GetInitials(user.Username);

            var library = await GameService.GetLibraryAsync(_targetUsername);
            var wishlist = await GameService.GetWishlistAsync(_targetUsername);

            TotalGames = library.Count;
            WishlistCount = wishlist.Count;

            var groups = library
                .GroupBy(g => g.Platform)
                .Select(grp => new PlatformGroupViewModel
                {
                    Platform = grp.Key,
                    Games = grp.ToList()
                })
                .OrderBy(g => g.Platform)
                .ToList();

            PlatformCount = groups.Count;
            GamesByPlatform = new System.Collections.ObjectModel.ObservableCollection<PlatformGroupViewModel>(groups);
        }
        finally
        {
            IsLoading = false;
        }
    }
}
