using Microsoft.UI.Dispatching;
using Sandouq.Models;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sandouq.Services;

public class ClipboardWatcher : IDisposable
{
    private readonly DispatcherTimer _timer;
    private readonly DispatcherQueue _dispatcherQueue;
    private string _lastHash = string.Empty;
    private readonly string _dataFilePath;
    private readonly string _encryptionKeyPath;
    private byte[] _encryptionKey;
    private readonly ObservableCollection<ClipItem> _clipItems;

    // P/Invoke for getting foreground window
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    public event EventHandler<ClipItem>? ClipboardContentChanged;

    public ClipboardWatcher(DispatcherQueue dispatcherQueue)
    {
        _dispatcherQueue = dispatcherQueue;
        _clipItems = new ObservableCollection<ClipItem>();

        // Setup paths
        string appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Sandouq"
        );

        if (!Directory.Exists(appDataPath))
        {
            Directory.CreateDirectory(appDataPath);
        }

        _dataFilePath = Path.Combine(appDataPath, "clips.enc");
        _encryptionKeyPath = Path.Combine(appDataPath, "encryption.key");

        // Initialize encryption key
        _encryptionKey = InitializeEncryptionKey();

        // Load existing data
        LoadClipsFromFile();

        // Setup timer
        _timer = new DispatcherTimer();
        _timer.Interval = TimeSpan.FromMilliseconds(800);
        _timer.Tick += Timer_Tick;
    }

    public void Start()
    {
        _timer.Start();
    }

    public void Stop()
    {
        _timer.Stop();
    }

    private void Timer_Tick(object? sender, object e)
    {
        try
        {
            var clipboardText = GetClipboardText();
            
            if (!string.IsNullOrEmpty(clipboardText))
            {
                string hash = ComputeSHA256Hash(clipboardText);

                // Only process if content is new
                if (hash != _lastHash)
                {
                    _lastHash = hash;

                    var sourceApp = GetSourceApplication();
                    var clipItem = CreateClipItem(clipboardText, hash, sourceApp);

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        _clipItems.Add(clipItem);
                        ClipboardContentChanged?.Invoke(this, clipItem);
                    });

                    // Save to encrypted file
                    SaveClipsToFile();
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error in clipboard watcher: {ex.Message}");
        }
    }

    private string GetClipboardText()
    {
        try
        {
            var content = Windows.ApplicationModel.DataTransfer.Clipboard.GetContent();

            if (content.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.Text))
            {
                return Windows.ApplicationModel.DataTransfer.Clipboard.GetContent()
                    .GetTextAsync()
                    .AsTask()
                    .Result;
            }
        }
        catch
        {
            // Clipboard access might fail due to permissions or other reasons
        }

        return string.Empty;
    }

    private string ComputeSHA256Hash(string input)
    {
        using (var sha256 = SHA256.Create())
        {
            byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToBase64String(hashedBytes);
        }
    }

    private string GetSourceApplication()
    {
        try
        {
            IntPtr foregroundWindowHandle = GetForegroundWindow();

            if (foregroundWindowHandle != IntPtr.Zero)
            {
                GetWindowThreadProcessId(foregroundWindowHandle, out uint processId);

                if (processId != 0)
                {
                    Process process = Process.GetProcessById((int)processId);
                    return Path.GetFileNameWithoutExtension(process.ProcessName);
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error getting source application: {ex.Message}");
        }

        return "Unknown";
    }

    private ClipItem CreateClipItem(string content, string hash, string sourceApp)
    {
        var now = DateTimeOffset.Now;
        
        return new ClipItem
        {
            Id = Guid.NewGuid(),
            Content = content,
            Hash = hash,
            Count = 1,
            FirstSeen = now,
            LastSeen = now,
            SourceApp = sourceApp,
            Classification = ClassifyContent(content),
            Language = DetectLanguage(content),
            Note = string.Empty,
            Tags = new ObservableCollection<string>(),
            IsFavorite = false,
            IsPassword = DetectPassword(content)
        };
    }

    private string ClassifyContent(string content)
    {
        if (Uri.TryCreate(content, UriKind.Absolute, out _))
            return "Link";

        if (content.Contains("@") && content.Contains("."))
            return "Email";

        if (content.All(c => char.IsDigit(c) || c == '-' || c == ' '))
            return "Number";

        return "Text";
    }

    private string DetectLanguage(string content)
    {
        // Simple detection: check for Arabic Unicode range
        foreach (char c in content)
        {
            if (c >= '\u0600' && c <= '\u06FF')
                return "Arabic";
        }

        return "English";
    }

    private bool DetectPassword(string content)
    {
        // Simple heuristic: check for uppercase, lowercase, numbers, and special characters
        bool hasUpper = content.Any(char.IsUpper);
        bool hasLower = content.Any(char.IsLower);
        bool hasDigit = content.Any(char.IsDigit);
        bool hasSpecial = content.Any(c => !char.IsLetterOrDigit(c));

        return content.Length >= 8 && hasUpper && hasLower && hasDigit && hasSpecial;
    }

    private byte[] InitializeEncryptionKey()
    {
        if (File.Exists(_encryptionKeyPath))
        {
            return File.ReadAllBytes(_encryptionKeyPath);
        }

        // Generate new key
        using (var rng = RandomNumberGenerator.Create())
        {
            byte[] key = new byte[32]; // 256-bit key
            rng.GetBytes(key);
            File.WriteAllBytes(_encryptionKeyPath, key);
            return key;
        }
    }

    private void SaveClipsToFile()
    {
        try
        {
            var json = JsonSerializer.Serialize(_clipItems.ToList());
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(json);

            using (var aes = Aes.Create())
            {
                aes.Key = _encryptionKey;
                aes.GenerateIV();

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream())
                {
                    // Write IV at the beginning
                    ms.Write(aes.IV, 0, aes.IV.Length);

                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                        cs.FlushFinalBlock();
                    }

                    File.WriteAllBytes(_dataFilePath, ms.ToArray());
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error saving clips to file: {ex.Message}");
        }
    }

    private void LoadClipsFromFile()
    {
        try
        {
            if (!File.Exists(_dataFilePath))
                return;

            byte[] encryptedData = File.ReadAllBytes(_dataFilePath);

            using (var aes = Aes.Create())
            {
                aes.Key = _encryptionKey;

                // Extract IV from the beginning of the encrypted data
                byte[] iv = new byte[aes.IV.Length];
                Array.Copy(encryptedData, 0, iv, 0, iv.Length);
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream(encryptedData, iv.Length, encryptedData.Length - iv.Length))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var reader = new StreamReader(cs))
                {
                    string json = reader.ReadToEnd();
                    var loadedClips = JsonSerializer.Deserialize<List<ClipItem>>(json);

                    if (loadedClips != null)
                    {
                        foreach (var clip in loadedClips)
                        {
                            _clipItems.Add(clip);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error loading clips from file: {ex.Message}");
        }
    }

    public IReadOnlyList<ClipItem> GetAllClips() => _clipItems.AsReadOnly();

    public void Dispose()
    {
        Stop();
        _timer?.Dispose();
    }
}
