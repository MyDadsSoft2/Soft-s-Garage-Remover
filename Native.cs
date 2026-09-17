using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace SoftsGarageRemover;

internal static class Native
{
	public struct MemoryBasicInformation64
	{
		public ulong BaseAddress;

		public ulong AllocationBase;

		public uint AllocationProtect;

		public uint __alignment1;

		public ulong RegionSize;

		public uint State;

		public uint Protect;

		public uint Type;

		public uint __alignment2;
	}

	public struct XInputState
	{
		public uint dwPacketNumber;

		public XInputGamepad Gamepad;
	}

	public struct XInputGamepad
	{
		public ushort wButtons;

		public byte bLeftTrigger;

		public byte bRightTrigger;

		public short sThumbLX;

		public short sThumbLY;

		public short sThumbRX;

		public short sThumbRY;
	}

	public struct Input
	{
		public uint type;

		public InputUnion u;
	}

	[StructLayout(LayoutKind.Explicit)]
	public struct InputUnion
	{
		[FieldOffset(0)]
		public KeyboardInput ki;

		[FieldOffset(0)]
		public MouseInput mi;
	}

	public struct MouseInput
	{
		public int dx;

		public int dy;

		public uint mouseData;

		public uint dwFlags;

		public uint time;

		public IntPtr dwExtraInfo;
	}

	public struct KeyboardInput
	{
		public ushort wVk;

		public ushort wScan;

		public uint dwFlags;

		public uint time;

		public IntPtr dwExtraInfo;
	}

	public struct PointStruct
	{
		public int x;

		public int y;
	}

	public struct Rect
	{
		public int Left;

		public int Top;

		public int Right;

		public int Bottom;
	}

	public struct Msllhookstruct
	{
		public PointStruct pt;

		public uint mouseData;

		public uint flags;

		public uint time;

		public IntPtr dwExtraInfo;
	}

	public delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	private struct TokPriv1Luid
	{
		public int Count;

		public long Luid;

		public int Attr;
	}

	public const uint ProcessAllAccess = 2035711u;

	public const uint MemCommit = 4096u;

	public const uint MemReserve = 8192u;

	public const uint MemCommitReserve = 12288u;

	public const uint MemRelease = 32768u;

	public const uint PageReadWrite = 4u;

	public const uint PageWriteCopy = 8u;

	public const uint PageExecute = 16u;

	public const uint PageExecuteRead = 32u;

	public const uint PageExecuteReadWrite = 64u;

	public const uint PageExecuteWriteCopy = 128u;

	public const uint PageNoAccess = 1u;

	public const uint PageGuard = 256u;

	public const int SwRestore = 9;

	public const int WmHotkey = 786;

	public const int WmSettingChange = 26;

	public const int WmDwmColorizationColorChanged = 800;

	public const int WhMouseLl = 14;

	public const int WmLButtonDown = 513;

	public const ushort ushort_0 = 1;

	public const ushort XInputGamepadDpadDown = 2;

	public const ushort XInputGamepadDpadLeft = 4;

	public const ushort XInputGamepadDpadRight = 8;

	public const ushort XInputGamepadLeftShoulder = 256;

	private const uint InputMouse = 0u;

	private const uint InputKeyboard = 1u;

	private const uint uint_0 = 2u;

	private const uint MouseEventFLeftUp = 4u;

	private const uint uint_1 = 1u;

	private const uint KeyEventFKeyUp = 2u;

	private const uint KeyEventFScancode = 8u;

	private const uint MapvkVkToVscEx = 4u;

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool CloseHandle(IntPtr hObject);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr dwSize, out UIntPtr lpNumberOfBytesRead);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

	[DllImport("kernel32.dll")]
	public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MemoryBasicInformation64 lpBuffer, UIntPtr dwLength);

	[DllImport("user32.dll")]
	public static extern short GetAsyncKeyState(int vKey);

	[DllImport("user32.dll")]
	public static extern IntPtr GetForegroundWindow();

	[DllImport("user32.dll")]
	public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int processId);

	[DllImport("user32.dll")]
	public static extern bool SetForegroundWindow(IntPtr hWnd);

	[DllImport("user32.dll")]
	public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

	[DllImport("user32.dll")]
	public static extern bool GetWindowRect(IntPtr hWnd, out Rect lpRect);

	[DllImport("user32.dll")]
	public static extern bool SetCursorPos(int x, int y);

	[DllImport("user32.dll", SetLastError = true)]
	public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelMouseProc lpfn, IntPtr hMod, uint dwThreadId);

	[DllImport("user32.dll", SetLastError = true)]
	public static extern bool UnhookWindowsHookEx(IntPtr hhk);

	[DllImport("user32.dll")]
	public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

	[DllImport("user32.dll", SetLastError = true)]
	public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, int vk);

	[DllImport("user32.dll", SetLastError = true)]
	public static extern bool UnregisterHotKey(IntPtr hWnd, int id);

	[DllImport("user32.dll", SetLastError = true)]
	private static extern uint SendInput(uint nInputs, Input[] pInputs, int cbSize);

	[DllImport("user32.dll")]
	private static extern uint MapVirtualKey(uint uCode, uint uMapType);

	[DllImport("xinput1_4.dll")]
	private static extern uint XInputGetState(int dwUserIndex, out XInputState pState);

	[DllImport("xinput1_3.dll", EntryPoint = "XInputGetState")]
	private static extern uint XInputGetState_1(int dwUserIndex, out XInputState pState);

	[DllImport("xinput9_1_0.dll", EntryPoint = "XInputGetState")]
	private static extern uint XInputGetState_2(int dwUserIndex, out XInputState pState);

	[DllImport("dwmapi.dll")]
	private static extern int DwmGetColorizationColor(out uint colorizationColor, out bool opaqueBlend);

	[DllImport("dwmapi.dll")]
	private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int attributeValue, int attributeSize);

	[DllImport("winmm.dll", CharSet = CharSet.Unicode)]
	private static extern int mciSendString(string command, StringBuilder returnValue, int returnLength, IntPtr hwndCallback);

	[DllImport("winmm.dll", CharSet = CharSet.Unicode)]
	private static extern bool mciGetErrorString(int errorCode, StringBuilder errorText, int errorTextSize);

	[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
	private static extern bool OpenProcessToken(IntPtr processHandle, int desiredAccess, ref IntPtr tokenHandle);

	[DllImport("advapi32.dll", SetLastError = true)]
	private static extern bool LookupPrivilegeValue(string host, string name, ref long luid);

	[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
	private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges, ref TokPriv1Luid newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

	[DllImport("kernel32.dll")]
	private static extern IntPtr GetCurrentProcess();

	[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public static extern IntPtr GetModuleHandle(string lpModuleName);

	public static bool TryXInputGetState(int userIndex, out XInputState state)
	{
		try
		{
			if (XInputGetState(userIndex, out state) == 0)
			{
				return true;
			}
		}
		catch
		{
		}
		try
		{
			if (XInputGetState_1(userIndex, out state) == 0)
			{
				return true;
			}
		}
		catch
		{
		}
		try
		{
			if (XInputGetState_2(userIndex, out state) == 0)
			{
				return true;
			}
		}
		catch
		{
		}
		state = default(XInputState);
		return false;
	}

	public static bool IsReadable(uint protect)
	{
		if ((protect & 0x100) != 0)
		{
			return false;
		}
		if ((protect & 1) != 0)
		{
			return false;
		}
		return protect != 0;
	}

	public static bool IsExecutable(uint protect)
	{
		if ((protect & 0x100) != 0)
		{
			return false;
		}
		if ((protect & 1) != 0)
		{
			return false;
		}
		uint num = protect & 0xFF;
		if (num != 16 && num != 32 && num != 64)
		{
			return num == 128;
		}
		return true;
	}

	public static bool IsAdministrator()
	{
		try
		{
			WindowsIdentity current = WindowsIdentity.GetCurrent();
			WindowsPrincipal windowsPrincipal = new WindowsPrincipal(current);
			return windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch
		{
			return false;
		}
	}

	public static void ApplySystemTitleBarColor(IntPtr handle)
	{
		if (!(handle == IntPtr.Zero) && DwmGetColorizationColor(out var colorizationColor, out var _) == 0)
		{
			byte r = (byte)((colorizationColor >> 16) & 0xFF);
			byte g = (byte)((colorizationColor >> 8) & 0xFF);
			byte b = (byte)(colorizationColor & 0xFF);
			int attributeValue = ToColorRef(r, g, b);
			int attributeValue2 = GetReadableTitleTextColor(r, g, b);
			DwmSetWindowAttribute(handle, 35, ref attributeValue, 4);
			DwmSetWindowAttribute(handle, 34, ref attributeValue, 4);
			DwmSetWindowAttribute(handle, 36, ref attributeValue2, 4);
		}
	}

	public static bool TryPlayMp3File(string path, out string error)
	{
		error = string.Empty;
		if (string.IsNullOrWhiteSpace(path))
		{
			error = "Audio path was empty.";
			return false;
		}
		string text = "lunaTeleportSaved" + Environment.TickCount.ToString("X", CultureInfo.InvariantCulture);
		bool flag = false;
		try
		{
			int num = mciSendString("open \"" + path + "\" type mpegvideo alias " + text, null, 0, IntPtr.Zero);
			if (num != 0)
			{
				error = GetMciError(num);
				return false;
			}
			flag = true;
			num = mciSendString("play " + text + " wait", null, 0, IntPtr.Zero);
			if (num != 0)
			{
				error = GetMciError(num);
				return false;
			}
			return true;
		}
		finally
		{
			if (flag)
			{
				mciSendString("close " + text, null, 0, IntPtr.Zero);
			}
		}
	}

	private static string GetMciError(int code)
	{
		StringBuilder stringBuilder = new StringBuilder(256);
		if (mciGetErrorString(code, stringBuilder, stringBuilder.Capacity))
		{
			return stringBuilder.ToString();
		}
		return "MCI error " + code.ToString(CultureInfo.InvariantCulture);
	}

	private static int ToColorRef(byte r, byte g, byte b)
	{
		return r | (g << 8) | (b << 16);
	}

	private static int GetReadableTitleTextColor(byte r, byte g, byte b)
	{
		double num = 0.2126 * (double)(int)r + 0.7152 * (double)(int)g + 0.0722 * (double)(int)b;
		if (!(num < 140.0))
		{
			return 0;
		}
		return 16777215;
	}

	public static void EnableDebugPrivilege()
	{
		try
		{
			IntPtr tokenHandle = IntPtr.Zero;
			if (OpenProcessToken(GetCurrentProcess(), 40, ref tokenHandle))
			{
				long luid = 0L;
				if (LookupPrivilegeValue(null, "SeDebugPrivilege", ref luid))
				{
					TokPriv1Luid newState = new TokPriv1Luid
					{
						Count = 1,
						Luid = luid,
						Attr = 2
					};
					AdjustTokenPrivileges(tokenHandle, disableAllPrivileges: false, ref newState, 0, IntPtr.Zero, IntPtr.Zero);
					CloseHandle(tokenHandle);
				}
			}
		}
		catch
		{
		}
	}

	public static void SendKeyboardKey(ushort virtualKey)
	{
		uint num = MapVirtualKey(virtualKey, 4u);
		if (num != 0)
		{
			ushort wScan = (ushort)(num & 0xFF);
			uint num2 = 8u;
			if ((num & 0xFF00) != 0 || IsExtendedVirtualKey(virtualKey))
			{
				num2 |= 1;
			}
			Input[] array = new Input[2]
			{
				new Input
				{
					type = 1u,
					u = new InputUnion
					{
						ki = new KeyboardInput
						{
							wVk = 0,
							wScan = wScan,
							dwFlags = num2,
							time = 0u,
							dwExtraInfo = IntPtr.Zero
						}
					}
				},
				new Input
				{
					type = 1u,
					u = new InputUnion
					{
						ki = new KeyboardInput
						{
							wVk = 0,
							wScan = wScan,
							dwFlags = (num2 | 2),
							time = 0u,
							dwExtraInfo = IntPtr.Zero
						}
					}
				}
			};
			SendInput((uint)array.Length, array, Marshal.SizeOf(typeof(Input)));
		}
		else
		{
			Input[] array2 = new Input[2]
			{
				new Input
				{
					type = 1u,
					u = new InputUnion
					{
						ki = new KeyboardInput
						{
							wVk = virtualKey,
							wScan = 0,
							dwFlags = 0u,
							time = 0u,
							dwExtraInfo = IntPtr.Zero
						}
					}
				},
				new Input
				{
					type = 1u,
					u = new InputUnion
					{
						ki = new KeyboardInput
						{
							wVk = virtualKey,
							wScan = 0,
							dwFlags = 2u,
							time = 0u,
							dwExtraInfo = IntPtr.Zero
						}
					}
				}
			};
			SendInput((uint)array2.Length, array2, Marshal.SizeOf(typeof(Input)));
		}
	}

	public static void SendMouseLeftClick(int x, int y)
	{
		SetCursorPos(x, y);
		Thread.Sleep(35);
		Input[] array = new Input[2]
		{
			new Input
			{
				type = 0u,
				u = new InputUnion
				{
					mi = new MouseInput
					{
						dx = 0,
						dy = 0,
						mouseData = 0u,
						dwFlags = 2u,
						time = 0u,
						dwExtraInfo = IntPtr.Zero
					}
				}
			},
			new Input
			{
				type = 0u,
				u = new InputUnion
				{
					mi = new MouseInput
					{
						dx = 0,
						dy = 0,
						mouseData = 0u,
						dwFlags = 4u,
						time = 0u,
						dwExtraInfo = IntPtr.Zero
					}
				}
			}
		};
		SendInput((uint)array.Length, array, Marshal.SizeOf(typeof(Input)));
	}

	private static bool IsExtendedVirtualKey(ushort virtualKey)
	{
		switch ((Keys)virtualKey)
		{
		default:
			return false;
		case Keys.Prior:
		case Keys.Next:
		case Keys.End:
		case Keys.Home:
		case Keys.Left:
		case Keys.Up:
		case Keys.Right:
		case Keys.Down:
		case Keys.Insert:
		case Keys.Delete:
		case Keys.RControlKey:
		case Keys.RMenu:
			return true;
		}
	}
}
