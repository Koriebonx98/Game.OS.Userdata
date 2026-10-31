using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Input;
using Avalonia.Threading;
using AvaloniaWebView;
using GameLauncher.Services;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

/// <summary>
/// Hosts one WebView per tab, drives the in-page virtual mouse from the controller (left stick),
/// and applies the ad blocker. The cursor is drawn inside the page (a native WebView always paints above Avalonia content).
/// </summary>
public partial class BrowserView : UserControl
{
    private readonly Dictionary<Guid, WebView> _webViews = new();
    private readonly BrowserGamepad _pad = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(16) };
    private BrowserViewModel? _vm;
    private double _cx = 200, _cy = 200, _sentX = -1, _sentY = -1;
    private double _menuAccum, _kbAccumX, _kbAccumY;
    private int _tick;
    private bool _scriptBusy;
    private double _pendingScroll;
    private string _pageScript = "";

    public BrowserView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => Bind();
        AttachedToVisualTree += (_, _) => _timer.Start();
        DetachedFromVisualTree += (_, _) => _timer.Stop();
        _timer.Tick += OnTick;
        WirePad();
    }

    private void Bind()
    {
        if (_vm != null) Unbind(_vm);
        _vm = DataContext as BrowserViewModel;
        if (_vm == null) return;
        _vm.NavigateRequested += OnNavigate;
        _vm.TabAdded += OnTabAdded;
        _vm.TabClosed += OnTabClosed;
        _vm.TabSelected += OnTabSelected;
        _vm.GoBackRequested += () => Run("history.back()");
        _vm.GoForwardRequested += () => Run("history.forward()");
        _vm.ReloadRequested += () => Run("location.reload()");
        _vm.FocusAddressRequested += FocusAddress;
        _vm.PropertyChanged += OnVmPropertyChanged;
        _vm.Keyboard.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(OnScreenKeyboardViewModel.IsOpen)) UpdateVisibility(); };
        foreach (var t in _vm.Tabs) OnTabAdded(t);
        UpdateVisibility();
    }

    private void Unbind(BrowserViewModel vm)
    {
        vm.NavigateRequested -= OnNavigate;
        vm.TabAdded -= OnTabAdded;
        vm.TabClosed -= OnTabClosed;
        vm.TabSelected -= OnTabSelected;
        vm.PropertyChanged -= OnVmPropertyChanged;
    }

    private void OnVmPropertyChanged(object? s, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(BrowserViewModel.IsMenuOpen) or nameof(BrowserViewModel.SuspendWebView) or nameof(BrowserViewModel.IsActive) or nameof(BrowserViewModel.ActiveTab))
            UpdateVisibility();
        if (e.PropertyName is nameof(BrowserViewModel.MenuIndex) or nameof(BrowserViewModel.IsMenuOpen))
            Dispatcher.UIThread.Post(HighlightMenu, DispatcherPriority.Background);
        if (e.PropertyName == nameof(BrowserViewModel.IsActive) && _vm?.IsActive == true)
        {
            _pad.CursorSpeed = _vm.Settings.CursorSpeed;
            _pad.ScrollSpeed = _vm.Settings.ScrollSpeed;
            _pad.Reset();
            UpdatePageScript();
            if (_vm.Tabs.Count == 0) _vm.EnsureTab();
        }
    }

    private void UpdatePageScript()
    {
        if (_vm == null) return;
        string? host = ActiveHost();
        string? block = _vm.Settings.AdBlockEnabled ? AdBlockService.BuildPageScript(host, _vm.Settings.AdBlockCosmetic, _vm.Settings.BlockPopups) : null;
        _pageScript = CursorScript + (block ?? "");
    }

    private string? ActiveHost()
    {
        string? url = _vm?.ActiveTab?.Url;
        return Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : null;
    }

    private void UpdateVisibility()
    {
        if (_vm == null) return;
        bool show = _vm.IsActive && !_vm.IsMenuOpen && !_vm.SuspendWebView && !_vm.Keyboard.IsOpen;
        foreach (var (id, wv) in _webViews)
            wv.IsVisible = show && _vm.ActiveTab?.Id == id;
    }

    // ── Tabs / WebViews ───────────────────────────────────────────────────

    private void OnTabAdded(BrowserTabVm tab)
    {
        if (_webViews.ContainsKey(tab.Id)) return;
        var wv = new WebView { HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Stretch, VerticalAlignment = Avalonia.Layout.VerticalAlignment.Stretch, IsVisible = false };
        wv.NavigationStarting += (_, e) => OnNavigationStarting(tab, e);
        wv.NavigationCompleted += (_, e) => OnNavigationCompleted(tab, wv, e);
        wv.WebViewNewWindowRequested += (_, e) => OnNewWindow(tab, e);
        _webViews[tab.Id] = wv;
        this.FindControl<Panel>("WebHost")!.Children.Insert(0, wv);
    }

    private void OnTabClosed(BrowserTabVm tab)
    {
        if (!_webViews.Remove(tab.Id, out var wv)) return;
        this.FindControl<Panel>("WebHost")!.Children.Remove(wv);
    }

    private void OnTabSelected(BrowserTabVm? tab)
    {
        UpdateVisibility();
        UpdatePageScript();
    }

    private void OnNavigate(BrowserTabVm tab, string url)
    {
        if (!_webViews.TryGetValue(tab.Id, out var wv)) return;
        if (_vm != null && _vm.Settings.AdBlockEnabled && AdBlockService.ShouldBlock(url, null))
        {
            _vm.StatusText = "🛡 Blocked by ad blocker";
            return;
        }
        tab.IsLoading = true;
        if (Uri.TryCreate(url, UriKind.Absolute, out var u)) wv.Url = u;
    }

    private void OnNavigationStarting(BrowserTabVm tab, dynamic e)
    {
        try
        {
            string url = e.Url?.ToString() ?? "";
            if (_vm == null || url.Length == 0) return;
            if (_vm.Settings.InterceptDownloads && DownloadManagerService.LooksLikeDownload(url))
            {
                e.Cancel = true;
                Dispatcher.UIThread.Post(() => StartDownload(tab, url));
                return;
            }
            if (_vm.Settings.InterceptDownloads && !_probeBypass.Remove(url) && DownloadManagerService.LooksLikeDownloadEndpoint(url))
            {
                // Extension-less file links: hold the navigation, ask the server what it is, then download or resume navigating.
                e.Cancel = true;
                Dispatcher.UIThread.Post(() => _ = ProbeAndRouteAsync(tab, url));
                return;
            }
            if (_vm.Settings.AdBlockEnabled && AdBlockService.ShouldBlock(url, ActiveHost()))
            {
                e.Cancel = true;
                Dispatcher.UIThread.Post(() => _vm.StatusText = $"🛡 Blocked {new Uri(url).Host}");
                return;
            }
            Dispatcher.UIThread.Post(() => { tab.IsLoading = true; _vm.UpdateTab(tab, url, null); });
        }
        catch { /* never throw into the web view */ }
    }

    private async void OnNavigationCompleted(BrowserTabVm tab, WebView wv, dynamic e)
    {
        try
        {
            string url = e.Url?.ToString() ?? tab.Url;
            await Dispatcher.UIThread.InvokeAsync(() => { tab.IsLoading = false; _vm?.UpdateTab(tab, url, null); });
            if (_vm?.ActiveTab == tab) UpdatePageScript();
            string? title = await wv.ExecuteScriptAsync("document.title");
            title = Unquote(title);
            await Dispatcher.UIThread.InvokeAsync(() => _vm?.UpdateTab(tab, url, string.IsNullOrWhiteSpace(title) ? new Uri(url).Host : title));
            await InjectAsync(wv);
        }
        catch { /* page may have navigated away */ }
    }

    private readonly HashSet<string> _probeBypass = new();

    private async Task ProbeAndRouteAsync(BrowserTabVm tab, string url)
    {
        if (_vm == null) return;
        string referer = tab.Url ?? "";
        string cookie = await GetCookieAsync(tab);
        bool isFile = await DownloadManagerService.ProbeIsDownloadAsync(url, referer, cookie);
        if (isFile) { _vm.RequestDownload(url, referer, cookie); return; }
        _probeBypass.Add(url);
        OnNavigate(tab, url);
    }

    private async Task<string> GetCookieAsync(BrowserTabVm tab)
    {
        try
        {
            if (_webViews.TryGetValue(tab.Id, out var wv))
                return Unquote(await wv.ExecuteScriptAsync("document.cookie")) ?? "";
        }
        catch { }
        return "";
    }

    private async void StartDownload(BrowserTabVm tab, string url)
    {
        if (_vm == null) return;
        string cookie = await GetCookieAsync(tab);
        _vm.RequestDownload(url, tab.Url ?? "", cookie);
    }

    private void OnNewWindow(BrowserTabVm from, dynamic e)
    {
        try
        {
            string url = e.Url?.ToString() ?? "";
            e.Handled = true;
            if (url.Length == 0 || _vm == null) return;
            if (_vm.Settings.InterceptDownloads && DownloadManagerService.LooksLikeDownload(url))
                Dispatcher.UIThread.Post(() => StartDownload(from, url));
            else if (_vm.Settings.InterceptDownloads && DownloadManagerService.LooksLikeDownloadEndpoint(url))
                Dispatcher.UIThread.Post(() => _ = ProbeAndRouteAsync(from, url));
            else if (!(_vm.Settings.BlockPopups && _vm.Settings.AdBlockEnabled && AdBlockService.ShouldBlock(url, null)))
                Dispatcher.UIThread.Post(() => _vm.NewTab(url));
        }
        catch { }
    }

    private static string? Unquote(string? s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        try { return JsonSerializer.Deserialize<string>(s); } catch { return s.Trim('"'); }
    }

    private WebView? Active => _vm?.ActiveTab != null && _webViews.TryGetValue(_vm.ActiveTab.Id, out var w) ? w : null;

    private async Task InjectAsync(WebView wv)
    {
        if (string.IsNullOrEmpty(_pageScript)) UpdatePageScript();
        try { await wv.ExecuteScriptAsync(_pageScript); } catch { }
    }

    private async void Run(string script)
    {
        try { var w = Active; if (w != null) await w.ExecuteScriptAsync(script); } catch { }
    }

    // ── Controller ────────────────────────────────────────────────────────

    private void WirePad()
    {
        _pad.OnCursorMove = (dx, dy) =>
        {
            if (_vm?.Keyboard.IsOpen == true)
            {
                _kbAccumX += dx; _kbAccumY += dy;
                if (Math.Abs(_kbAccumX) > 45) { _vm.Keyboard.Move(_kbAccumX > 0 ? 1 : -1, 0); _kbAccumX = 0; }
                if (Math.Abs(_kbAccumY) > 45) { _vm.Keyboard.Move(0, _kbAccumY > 0 ? 1 : -1); _kbAccumY = 0; }
                return;
            }
            if (_vm?.IsMenuOpen == true)
            {
                _menuAccum += dy;
                if (Math.Abs(_menuAccum) > 45) { _vm.MoveMenu(_menuAccum > 0 ? 1 : -1); _menuAccum = 0; }
                return;
            }
            if (WebHostBounds() is not { } b) return;
            _cx = Math.Clamp(_cx + dx, 0, Math.Max(1, b.Width - 1));
            _cy = Math.Clamp(_cy + dy, 0, Math.Max(1, b.Height - 1));
        };
        _pad.OnScroll = dy => { if (_vm?.IsMenuOpen != true && _vm?.Keyboard.IsOpen != true) _pendingScroll += dy; };
        _pad.OnDpad = (dx, dy) =>
        {
            if (_vm == null) return;
            if (_vm.Keyboard.IsOpen) { _vm.Keyboard.Move(dx, dy); return; }
            if (_vm.Downloads?.IsPromptOpen == true) { _vm.Downloads.PromptMove(dx, dy); return; }
            if (_vm.IsMenuOpen && dy != 0) _vm.MoveMenu(dy);
        };
        _pad.OnA = () =>
        {
            if (_vm == null) return;
            if (_vm.Keyboard.IsOpen) { _vm.Keyboard.PressSelected(); return; }
            if (_vm.Downloads?.IsPromptOpen == true) { _vm.Downloads.PromptActivate(); return; }
            if (_vm.IsMenuOpen) { _vm.ActivateMenu(); return; }
            Click(false);
        };
        _pad.OnX = () =>
        {
            if (_vm == null) return;
            if (_vm.Keyboard.IsOpen) { _vm.Keyboard.Backspace(); return; }
            if (_vm.IsMenuOpen) { _vm.RemoveSelectedFavourite(); return; }
            if (_vm.Downloads?.IsPromptOpen == true) return;
            Click(true);
        };
        _pad.OnY = () =>
        {
            if (_vm == null || _vm.Downloads?.IsPromptOpen == true) return;
            if (_vm.Keyboard.IsOpen) { _vm.Keyboard.HandleKey("Y"); return; }
            _vm.CloseMenu();
            FocusAddress();
        };
        _pad.OnB = () =>
        {
            if (_vm == null) return;
            if (_vm.Keyboard.IsOpen) { _vm.Keyboard.Close(); return; }
            if (_vm.Downloads?.IsPromptOpen == true) { _vm.Downloads.CancelPromptCommand.Execute(null); return; }
            if (_vm.IsMenuOpen) { _vm.CloseMenu(); return; }
            _vm.GoBack();
        };
        _pad.OnStart = () => { if (_vm?.Downloads?.IsPromptOpen != true && _vm?.Keyboard.IsOpen != true) _vm?.ToggleMenu(); };
        _pad.OnLb = () => { if (_vm?.IsMenuOpen != true && _vm?.Keyboard.IsOpen != true && _vm?.Downloads?.IsPromptOpen != true) _vm?.PreviousTab(); };
        _pad.OnRb = () => { if (_vm?.IsMenuOpen != true && _vm?.Keyboard.IsOpen != true && _vm?.Downloads?.IsPromptOpen != true) _vm?.NextTab(); };
    }

    private Rect? WebHostBounds() => this.FindControl<Panel>("WebHost")?.Bounds;

    private async void Click(bool right)
    {
        var w = Active;
        if (w == null) return;
        try
        {
            string res = Unquote(await w.ExecuteScriptAsync(right ? "window.__gos&&__gos.right()" : "window.__gos&&__gos.click()")) ?? "";
            if (res == "input" && _vm?.Settings.ShowOnScreenKeyboard == true) await OpenPageKeyboardAsync(w);
        }
        catch { }
    }

    /// <summary>Opens the launcher's on-screen keyboard bound to the web page input the virtual mouse just clicked.</summary>
    private async Task OpenPageKeyboardAsync(WebView w)
    {
        if (_vm == null) return;
        string initial = Unquote(await w.ExecuteScriptAsync("window.__gos?__gos.getText():''")) ?? "";
        _vm.Keyboard.Open(initial, "Type into the page", text => Run($"window.__gos&&__gos.setText({JsonSerializer.Serialize(text)})"),
            _ => Run("window.__gos&&__gos.submit()"));
    }

    private void FocusAddress()
    {
        var box = this.FindControl<TextBox>("AddressBox");
        if (box == null) return;
        if (_vm?.Settings.ShowOnScreenKeyboard == true)
        {
            _vm.Keyboard.Open(_vm.AddressText ?? "", "Search or enter address", t => _vm.AddressText = t, t => { _vm.AddressText = t; _vm.Go(null); });
            return;
        }
        box.Focus();
        box.SelectAll();
    }

    private void OnAddressKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { _vm?.Go(null); e.Handled = true; this.Focus(); }
        else if (e.Key == Key.Escape) { this.Focus(); e.Handled = true; }
    }

    private void OnMenuClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e) => _vm?.ToggleMenu();

    private void HighlightMenu()
    {
        var list = this.FindControl<ItemsControl>("MenuList");
        if (list == null || _vm == null) return;
        for (int i = 0; i < list.ItemCount; i++)
        {
            if (list.ContainerFromIndex(i) is { } c && c is ContentPresenter cp && cp.Child is Button btn)
            {
                btn.Classes.Set("menu-hl", i == _vm.MenuIndex);
                if (i == _vm.MenuIndex) btn.BringIntoView();
            }
        }
    }

    private async void OnTick(object? sender, EventArgs e)
    {
        if (_vm == null || !_vm.IsActive) return;
        _pad.Poll();
        _tick++;

        var w = Active;
        if (w == null || !w.IsVisible || _scriptBusy) return;

        string? script = null;
        if (Math.Abs(_pendingScroll) >= 1)
        {
            script = $"window.__gos&&__gos.scroll({_pendingScroll:F1})";
            _pendingScroll = 0;
        }
        else if (Math.Abs(_cx - _sentX) > 0.5 || Math.Abs(_cy - _sentY) > 0.5)
        {
            script = $"window.__gos&&__gos.move({_cx:F0},{_cy:F0})";
            _sentX = _cx; _sentY = _cy;
        }
        else if (_tick % 30 == 0)
        {
            // Keeps the cursor + ad blocker alive across client-side navigations and collects queued context-menu actions.
            script = _pageScript + ";window.__gos?__gos.drain():'[]'";
        }
        if (script == null) return;

        _scriptBusy = true;
        try
        {
            string? result = await w.ExecuteScriptAsync(script);
            if (_tick % 30 == 0) HandleQueue(Unquote(result));
        }
        catch { }
        finally { _scriptBusy = false; }
    }

    private void HandleQueue(string? json)
    {
        if (string.IsNullOrEmpty(json) || json == "[]" || _vm == null) return;
        try
        {
            foreach (var el in JsonDocument.Parse(json).RootElement.EnumerateArray())
            {
                string t = el.GetProperty("t").GetString() ?? "";
                string u = el.TryGetProperty("u", out var uu) ? uu.GetString() ?? "" : "";
                if (t == "tab" && u.Length > 0) _vm.NewTab(u);
                else if (t == "dl" && u.Length > 0 && _vm.ActiveTab != null) StartDownload(_vm.ActiveTab, u);
                else if (t == "probe" && u.Length > 0 && _vm.ActiveTab != null) _ = ProbeAndRouteAsync(_vm.ActiveTab, u);
            }
        }
        catch { }
    }

    // Cursor + virtual-mouse runtime injected into every page.
    private const string CursorScript = @"(function(){if(window.__gos)return;
var cur=document.createElement('div');cur.style.cssText='position:fixed;left:0;top:0;width:24px;height:24px;z-index:2147483647;pointer-events:none;display:none';
cur.innerHTML='<svg width=""24"" height=""24"" viewBox=""0 0 24 24""><path d=""M3 2 L3 19 L8 14.5 L11.5 22 L14.5 20.5 L11 13.5 L18 13.5 Z"" fill=""#fff"" stroke=""#000"" stroke-width=""1.4""/></svg>';
document.documentElement.appendChild(cur);
var x=200,y=200,q=[],menu=null,last=null,inp=null;
function under(){cur.style.display='none';var e=document.elementFromPoint(x,y);cur.style.display='block';return e;}
function fire(e,t,b){e.dispatchEvent(new MouseEvent(t,{bubbles:true,cancelable:true,view:window,clientX:x,clientY:y,button:b,buttons:b==2?2:(t=='mouseup'?0:1)}));}
function closeMenu(){if(menu){menu.remove();menu=null;}}
function isInput(e){return e&&(e.closest&&e.closest('input,textarea,select,[contenteditable=""true""],[contenteditable=""""]'));}
function scrollable(e){while(e&&e!==document.body&&e!==document.documentElement){var s=getComputedStyle(e);if((s.overflowY=='auto'||s.overflowY=='scroll')&&e.scrollHeight>e.clientHeight)return e;e=e.parentElement;}return null;}
function addItem(m,label,fn){var d=document.createElement('div');d.textContent=label;d.style.cssText='padding:8px 18px;color:#e6edf3;font:13px sans-serif;cursor:pointer;white-space:nowrap';d.__act=fn;m.appendChild(d);}
document.addEventListener('click',function(ev){var a=ev.target&&ev.target.closest?ev.target.closest('a[href]'):null;if(!a||!/^https?:/i.test(a.href))return;
 if(a.hasAttribute('download')){ev.preventDefault();ev.stopImmediatePropagation();q.push({t:'dl',u:a.href});}
 else if(/\/download|\/dl(\/|$)|[?&]download=/i.test(a.href)&&new URL(a.href).origin!==location.origin){ev.preventDefault();ev.stopImmediatePropagation();q.push({t:'probe',u:a.href});}},true);
window.__gos={
 move:function(nx,ny){x=nx;y=ny;cur.style.display='block';cur.style.transform='translate('+x+'px,'+y+'px)';var e=under();if(e&&e!==last){if(last)fire(last,'mouseout',0);fire(e,'mouseover',0);last=e;}if(e)fire(e,'mousemove',0);
  if(menu){for(var i=0;i<menu.children.length;i++){var c=menu.children[i],r=c.getBoundingClientRect();c.style.background=(x>=r.left&&x<=r.right&&y>=r.top&&y<=r.bottom)?'#1f6feb':'transparent';}}},
 click:function(){if(menu){var e0=under();var act=e0&&e0.__act;closeMenu();if(act)act();return '';}
  var e=under();if(!e)return '';fire(e,'mousedown',0);if(isInput(e)){var t=e.closest('input,textarea,select,[contenteditable]');t.focus();inp=t;fire(e,'mouseup',0);fire(e,'click',0);return 'input';}
  fire(e,'mouseup',0);if(e.click)e.click();else fire(e,'click',0);return '';},
 right:function(){closeMenu();var e=under();if(!e)return '';fire(e,'contextmenu',2);var a=e.closest('a[href]');
  menu=document.createElement('div');menu.style.cssText='position:fixed;z-index:2147483647;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:6px 0;box-shadow:0 8px 24px rgba(0,0,0,.5);left:'+Math.min(x,innerWidth-200)+'px;top:'+Math.min(y,innerHeight-220)+'px';
  if(a){addItem(menu,'Open link in new tab',function(){q.push({t:'tab',u:a.href});});addItem(menu,'Download link',function(){q.push({t:'dl',u:a.href});});addItem(menu,'Copy link address',function(){var i=document.createElement('textarea');i.value=a.href;document.body.appendChild(i);i.select();document.execCommand('copy');i.remove();});}
  if(e.tagName=='IMG'&&e.src)addItem(menu,'Open image in new tab',function(){q.push({t:'tab',u:e.src});});
  addItem(menu,'Back',function(){history.back();});addItem(menu,'Forward',function(){history.forward();});addItem(menu,'Reload',function(){location.reload();});
  document.documentElement.appendChild(menu);return '';},
 getText:function(){return inp?(inp.isContentEditable?inp.innerText:(inp.value||'')):'';},
 setText:function(v){if(!inp)return;if(inp.isContentEditable){inp.innerText=v;}else{var d=Object.getOwnPropertyDescriptor(inp.tagName=='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value');if(d&&d.set)d.set.call(inp,v);else inp.value=v;}inp.dispatchEvent(new Event('input',{bubbles:true}));inp.dispatchEvent(new Event('change',{bubbles:true}));},
 submit:function(){if(!inp)return;inp.focus();['keydown','keypress','keyup'].forEach(function(t){inp.dispatchEvent(new KeyboardEvent(t,{key:'Enter',code:'Enter',keyCode:13,which:13,bubbles:true}));});if(inp.form){if(inp.form.requestSubmit)inp.form.requestSubmit();else inp.form.submit();}},
 scroll:function(dy){var e=scrollable(under());if(e)e.scrollTop+=dy;else window.scrollBy(0,dy);},
 drain:function(){var r=JSON.stringify(q);q=[];return r;}
};})();";
}
