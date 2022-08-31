# If this script runs while no user is logged in, it will throw the error: Exception calling "StartProcessAsCurrentUser" with "4" argument(s): "StartProcessAsCurrentUser: GetSessionUserToken failed."
# To overcome that, we need to check for a logged in user. Additionally, OneDrive does not run unless a user is logged in as well, so we have two reasons to perform this checking
query user | out-file "C:\Users\Public\queryuser.txt" # when trying to send this directly to a variable, it sends information to stdout, so this needs to be output to a file instead.
$usersLoggedIn = (get-content "C:\Users\Public\queryuser.txt")
Remove-Item "C:\Users\Public\queryuser.txt" -ErrorAction SilentlyContinue

if ($usersLoggedIn -like '*No User exists*' -or $usersLoggedIn -eq $null -or $usersLoggedIn -eq "") {

  # Lets check to see how long it's been since we were able to get the status
  if ((Test-Path -Path "C:\Users\Public\OneDriveStatusFailing.txt")) {
    $lastDate = (Get-Content "C:\Users\Public\OneDriveStatusFailing.txt" | convertfrom-json).DateTime
    $elapsed = New-TimeSpan -Start $lastDate -End (get-date)

    # If no syncing for 7 days, we should go ahead and let RMM know syncing is not working.
    if ($elapsed.Days -ge 7) {
        Write-Host "ERROR: Unable to get OneDrive sync status for more than 7 days."
        exit 1001
    }
    else {
        Write-Host "Unable to get sync status, but threshold for failing the check has not yet been reached. Sync status has not been found in $($elapsed.Days) days."
        exit 0
    }
  }

  # The failing txt file doesn't exist yet, create it
  else {
    Get-Date | convertto-json | Out-File "C:\Users\Public\OneDriveStatusFailing.txt"
    Write-Host "Unable to get sync status, because the user is not logged in."

    # Ok with returning success for now
    exit 0
  }
}

# A user appears to be logged in, remove any failing txt files.
Remove-Item "C:\Users\Public\OneDriveStatusFailing.txt" -ErrorAction SilentlyContinue

# This part from https://www.cyberdrain.com/monitoring-with-powershell-monitoring-onedrive-status-for-current-logged-on-user/
$Source = @"
using System;
using System.Runtime.InteropServices;
namespace murrayju.ProcessExtensions
{
    public static class ProcessExtensions
    {
        #region Win32 Constants
        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;
        private const int CREATE_NEW_CONSOLE = 0x00000010;
        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;
        #endregion
        #region DllImports
        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);
        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);
        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();
        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);
        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);
        #endregion
        #region Win32 Structs
        private enum SW
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_MAX = 10
        }
        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;
            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;
            public readonly WTS_CONNECTSTATE_CLASS State;
        }
        #endregion
        // Gets the user token from the currently active session
        private static bool GetSessionUserToken(ref IntPtr phUserToken)
        {
            var bResult = false;
            var hImpersonationToken = IntPtr.Zero;
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;
            // Get a handle to the user access token for the current active session.
            if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
            {
                var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                var current = pSessionInfo;
                for (var i = 0; i < sessionCount; i++)
                {
                    var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                    current += arrayElementSize;
                    if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                    {
                        activeSessionId = si.SessionID;
                    }
                }
            }
            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = WTSGetActiveConsoleSessionId();
            }
            if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
            {
                // Convert the impersonation token to a primary token
                bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                    ref phUserToken);
                CloseHandle(hImpersonationToken);
            }
            return bResult;
        }
        public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true)
        {
            var hUserToken = IntPtr.Zero;
            var startInfo = new STARTUPINFO();
            var procInfo = new PROCESS_INFORMATION();
            var pEnv = IntPtr.Zero;
            int iResultOfCreateProcessAsUser;
            startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            try
            {
                if (!GetSessionUserToken(ref hUserToken))
                {
                    throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                }
                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                startInfo.lpDesktop = "winsta0\\default";
                if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                }
                if (!CreateProcessAsUser(hUserToken,
                    appPath, // Application Name
                    cmdLine, // Command Line
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    dwCreationFlags,
                    pEnv,
                    workDir, // Working directory
                    ref startInfo,
                    out procInfo))
                {
                    throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
                }
                iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
            }
            finally
            {
                CloseHandle(hUserToken);
                if (pEnv != IntPtr.Zero)
                {
                    DestroyEnvironmentBlock(pEnv);
                }
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }
            return true;
        }
    }
}
"@
Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $Source -Language CSharp 

# The file must be downloaded in the system context and unblocked before launching the user context
Invoke-WebRequest -Uri 'https://github.com/eneerge/NAble-RMM-Check-OneDrive-Status/raw/main/OneDriveLib.dll' -OutFile 'C:\Users\Public\OneDriveLib.dll'
Unblock-File "C:\Users\Public\OneDriveLib.dll"

# This script block runs in the user context
$scriptblock = {    
    Import-Module "C:\Users\Public\OneDriveLib.dll"

    # Write this file out each time the script is run so the outter System context will always have a file to read. If the Get-ODStatus fails to run, this will let us know.
    "ERROR: Unable to get status from ODStatus." | out-file "C:\Users\Public\onedrivestatus.txt"

    # The status must be written to a file so it can be accessed by the System User outside of this Standard User Context
    $status = Get-ODStatus -OnDemandOnly -Type Business # <------ I'm only looking for Business Onedrive here, you can also use "Personal"
    if ($status -ne $null) {
      $status | convertto-json | out-file "C:\Users\Public\onedrivestatus.txt"
    }
}

# Run the above script block as the logged in user
[murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser("C:\Windows\System32\WindowsPowershell\v1.0\Powershell.exe", "-command $($scriptblock)","C:\Windows\System32\WindowsPowershell\v1.0",$false) | Out-Null

# Must wait for the script block to finish before checking for the status
start-sleep 10

# Load the output of the status file
$rawContent = (get-content "C:\Users\Public\onedrivestatus.txt")

# If raw content is the error we created above, then script failed
if ($rawContent -eq "ERROR: Unable to get status from ODStatus.") {
  Write-Host "Failure occurred running script to get OneDrive status."
  exit 1001
}

# Not script failure, time to check the onedrive status
$odStatus = (get-content "C:\Users\Public\onedrivestatus.txt" | convertfrom-json)

$return = "";
$returnCode = 0;
foreach ($s in $odStatus) {
    
    # I'm filtering here for my company's name. Typically, when using OneDrive for Business, the OneDrive default folder looks like "OneDrive - The Company Name" for the user's Personal files.
    # Here, I'm just looking for *My Company Name* so I only pull in the Personal Onedrive folders.
    # The reason I am doing this is because the ODStatus tool will also return statuses for Sharepoint shares. However, I found the Sharepoint statuses inaccurate.
    # My primary concern is that their personal files are being backed up to OneDrive and so I filter that here.
    if ($s.DisplayName -like '*Replace With Your Company Name or Some Other Filter*') {
        # Known statuses accepted as healthy
        if ($s.StatusString -like "Looking for changes" `
            -or $s.StatusString -like "Up to date" `
            -or $s.StatusString -like "Processing*change*")
        {
            $returnStatus += "Healthy"
            # not setting a returncode here in case one of the other statuses are unhealthy and setting returncode back to 0 would wipe out that unhealthy status in the return back to RMM
        }

        # For any non-success status, then assume error
        else {
            $returnStatus += "ERROR: OneDrive status appears unhealthy. " + [System.Environment]::NewLine + $s
            $returnCode = 1001 # Anything over 1000 will trigger an RMM unsuccessful run
        }
    }
}

# Cleanup
Remove-Item "C:\Users\Public\onedrivestatus.txt"

# Return status to N-Able RMM
Write-Host $returnStatus
exit $returnCode;

# Known Statuses
# - Looking for changes
# - Up to date
# - Signing out
# - signing in
# - Processing X changes
# - Processing change
# - paused
# - <error>no status text found
# - You're not signed in
# - Not signed in
