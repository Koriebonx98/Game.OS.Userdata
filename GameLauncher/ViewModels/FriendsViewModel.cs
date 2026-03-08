using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;

namespace GameLauncher.ViewModels;

public partial class FriendsViewModel : ViewModelBase
{
    private List<Friend> _allFriends = new();

    [ObservableProperty] private string _searchText  = "";
    [ObservableProperty] private string _addUsername = "";
    [ObservableProperty] private string _statusMessage = "";

    public ObservableCollection<Friend> FilteredFriends { get; } = new();

    public int  OnlineCount      => _allFriends.Count(f => f.IsOnline);
    public int  OfflineCount     => _allFriends.Count(f => !f.IsOnline);
    public bool HasStatusMessage => !string.IsNullOrEmpty(StatusMessage);

    partial void OnStatusMessageChanged(string value) => OnPropertyChanged(nameof(HasStatusMessage));

    partial void OnSearchTextChanged(string value) => ApplyFilter();

    public void Load(List<Friend> friends)
    {
        _allFriends = friends;
        OnPropertyChanged(nameof(OnlineCount));
        OnPropertyChanged(nameof(OfflineCount));
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var q = SearchText.Trim().ToLowerInvariant();
        var filtered = string.IsNullOrEmpty(q)
            ? _allFriends
            : _allFriends.Where(f => f.Username.ToLowerInvariant().Contains(q));

        // Online first, then offline
        var sorted = filtered.OrderByDescending(f => f.IsOnline)
                             .ThenBy(f => f.Username)
                             .ToList();

        FilteredFriends.Clear();
        foreach (var f in sorted)
            FilteredFriends.Add(f);
    }

    [RelayCommand]
    private void AddFriend()
    {
        if (string.IsNullOrWhiteSpace(AddUsername))
        {
            StatusMessage = "Please enter a username.";
            return;
        }
        StatusMessage = $"Friend request sent to {AddUsername.Trim()}!";
        AddUsername   = "";
    }
}
