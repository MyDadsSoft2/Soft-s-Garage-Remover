using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SoftsGarageRemover;

public sealed class RemoteDatabase : IDisposable
{
	private struct DatabaseCandidate
	{
		public bool Valid;

		public ulong MatchAddress;

		public ulong PointerAddress;

		public ulong DatabaseObject;

		public ulong QueryFunction;
	}

	private struct MemoryPatch
	{
		public ulong Address;

		public byte[] Original;
	}

	private struct FovTableTarget
	{
		public string Name;

		public ulong Address;
	}

	private struct TimeAttackFloatCandidate
	{
		public ulong Address;

		public float Value;

		public ulong Anchor;

		public int PatchMode;
	}

	private sealed class RuntimeDetour
	{
		public string Name;

		public ulong Address;

		public ulong DetourAddress;

		public int Size;

		public byte[] Original;

		public byte[] Patch;
	}

	private sealed class LiveProfileCandidate
	{
		public ulong BaseAddress;

		public byte[] Data;
	}

	private sealed class LiveProfileIntegerMatch
	{
		public ulong BaseAddress;

		public ulong Address;

		public int BufferLength;

		public int Offset;

		public int Value;

		public int Size;

		public int Score;

		public string Key;
	}

	private struct MemoryRegion
	{
		public ulong BaseAddress;

		public ulong RegionSize;
	}

	private sealed class RuntimeProfileHookDescriptor
	{
		public string Key;

		public string Name;

		public string Signature;

		public string MetadataName = string.Empty;

		public int MetadataPointerOffset;

		public int MatchOffset;

		public bool ResolveCallTarget;

		public int CallTargetOffset;

		public int HookSize;

		public byte[] Asm;

		public byte[] ExpectedOriginal;

		public bool OriginalIsRelativeJump;

		public int ToggleOffset;

		public int ValueOffset;

		public int CaptureOffset = -1;

		public int ResetByteOffset = -1;

		public int ObjectPointerOffset = -1;

		public int ObjectValueFieldOffset = -1;

		public int MinimumSize;
	}

	private sealed class ProfileIntegerHookLayout
	{
		public byte[] Asm;

		public int CreditsToggleOffset;

		public int CreditsValueOffset;

		public int CreditsCaptureOffset;

		public int XpToggleOffset;

		public int XpValueOffset;

		public int XpCaptureOffset;

		public int MinimumSize;
	}

	private sealed class GravityHookLayout
	{
		public byte[] Asm;

		public int ToggleOffset;

		public int ValueOffset;

		public int CaptureOffset;

		public int MinimumSize;
	}

	private sealed class XpAggregateHookLayout
	{
		public byte[] Asm;

		public int ToggleOffset;

		public int ValueOffset;

		public int CaptureOffset;

		public int ObjectPointerOffset;

		public int MinimumSize;
	}

	private sealed class SimpleToggleHookLayout
	{
		public byte[] Asm;

		public int ToggleOffset;

		public int MinimumSize;
	}

	private sealed class VehicleControlHookLayout
	{
		public byte[] Asm;

		public int VehiclePointerOffset;

		public int TeleportToggleOffset;

		public int TeleportPositionOffset;

		public int SpeedToggleOffset;

		public int SpeedValueOffset;

		public int JumpToggleOffset;

		public int JumpValueOffset;

		public int BoostToggleOffset;

		public int BoostValueOffset;

		public int DriftModeToggleOffset;

		public int DriftModeValueOffset;

		public int GravityToggleOffset;

		public int GravityValueOffset;

		public int StabilizerToggleOffset;

		public int StabilizerValueOffset;

		public int HandlingToggleOffset;

		public int HandlingValueOffset;

		public int SlideToggleOffset;

		public int SlideValueOffset;

		public int RoadMagnetToggleOffset;

		public int RoadMagnetValueOffset;

		public int SpeedTamerToggleOffset;

		public int SpeedTamerValueOffset;

		public int AirLiftToggleOffset;

		public int AirLiftValueOffset;

		public int BounceCushionToggleOffset;

		public int BounceCushionValueOffset;

		public int MomentumToggleOffset;

		public int MomentumValueOffset;

		public int LeftRightToggleOffset;

		public int LeftRightValueOffset;

		public int ForwardBackToggleOffset;

		public int ForwardBackValueOffset;

		public int SidePushToggleOffset;

		public int SidePushValueOffset;

		public int ForwardPushToggleOffset;

		public int ForwardPushValueOffset;

		public int VerticalTrimToggleOffset;

		public int VerticalTrimValueOffset;

		public int SideLockToggleOffset;

		public int SideLockValueOffset;

		public int ForwardLockToggleOffset;

		public int ForwardLockValueOffset;

		public int VerticalHoldToggleOffset;

		public int VerticalHoldValueOffset;

		public int MotionFreezeToggleOffset;

		public int MotionFreezeValueOffset;

		public int WheelieBoostToggleOffset;

		public int WheelieBoostValueOffset;

		public int DriftKickToggleOffset;

		public int DriftKickValueOffset;

		public int HoverGlideToggleOffset;

		public int HoverGlideValueOffset;

		public int AirBrakeToggleOffset;

		public int AirBrakeValueOffset;

		public int CornerStabilizerToggleOffset;

		public int CornerStabilizerValueOffset;

		public int PlantedBoostToggleOffset;

		public int PlantedBoostValueOffset;

		public int ForwardLaunchToggleOffset;

		public int ForwardLaunchValueOffset;

		public int StraightLaunchToggleOffset;

		public int StraightLaunchValueOffset;

		public int DragLaunchAssistToggleOffset;

		public int DragLaunchAssistValueOffset;

		public int TireBiteToggleOffset;

		public int TireBiteValueOffset;

		public int GripLockToggleOffset;

		public int GripLockValueOffset;

		public int ForwardGripToggleOffset;

		public int ForwardGripValueOffset;

		public int RailGripToggleOffset;

		public int RailGripValueOffset;

		public int HighSpeedStabilizerToggleOffset;

		public int HighSpeedStabilizerValueOffset;

		public int GroundClampToggleOffset;

		public int GroundClampValueOffset;

		public int StabilityRailToggleOffset;

		public int StabilityRailValueOffset;

		public int AirControlToggleOffset;

		public int AirControlValueOffset;

		public int AirControlSideValueOffset;

		public int AirControlForwardValueOffset;

		public int CornerBiteToggleOffset;

		public int CornerBiteValueOffset;

		public int SpinRecoveryToggleOffset;

		public int SpinRecoveryValueOffset;

		public int MinimumSize;
	}

	private sealed class ProfileAsmFixup
	{
		public int Offset;

		public int InstructionEnd;

		public string Label;
	}

	public sealed class QueryResult
	{
		public readonly List<string> Columns = new List<string>();

		public readonly List<List<object>> Rows = new List<List<object>>();
	}

	private const int VirtualFunctionIndex = 9;

	private const int TimeAttackInfluenceScanTimeoutMs = 5000;

	private const int TimeAttackRecordScanTimeoutMs = 10000;

	private const int TimeAttackMaxBonusSlots = 14;

	private const ulong TimeAttackInfluenceMaxRegionRead = 33554432uL;

	private const int TimeAttackInfluenceMaxAnchors = 32;

	private const int TimeAttackInfluenceMaxReferences = 128;

	private const int XpProfileCandidateScanTimeoutMs = 150000;

	private const int TimeAttackPatchModeDirectMultiplier = 0;

	private const int TimeAttackPatchModeBonusDelta = 1;

	private const int JumpPulseMilliseconds = 140;

	private const int AirControlPulseMilliseconds = 34;

	private const float AirControlPushScale = 90f;

	private const float AirControlMinHorizontalPush = 12f;

	private const float AirControlMaxHorizontalPush = 72f;

	private const int SuperBrakeInstantStopMilliseconds = 1000;

	private const uint PageNoCache = 1024u;

	private readonly Process _process;

	private readonly Action<string> _log;

	private readonly List<DatabaseCandidate> _candidates = new List<DatabaseCandidate>();

	private readonly List<MemoryPatch> _memoryPatches = new List<MemoryPatch>();

	private readonly List<MemoryPatch> _timeAttackInfluencePatches = new List<MemoryPatch>();

	private readonly List<MemoryPatch> _bestWheelspinOddsPatches = new List<MemoryPatch>();

	private readonly List<MemoryPatch> _fovTablePatches = new List<MemoryPatch>();

	private readonly List<ulong> _bestWheelspinOddsDetours = new List<ulong>();

	private readonly List<TimeAttackFloatCandidate> _timeAttackInfluenceCachedCandidates = new List<TimeAttackFloatCandidate>();

	private readonly List<ulong> _timeAttackInfluenceStringAddresses = new List<ulong>();

	private readonly List<ulong> _timeAttackInfluenceReferenceAddresses = new List<ulong>();

	private readonly Dictionary<string, RuntimeDetour> _runtimeProfileHooks = new Dictionary<string, RuntimeDetour>(StringComparer.OrdinalIgnoreCase);

	private readonly object _runtimePatchLock = new object();

	private readonly object _timeAttackPatchLock = new object();

	private readonly object _bestWheelspinPatchLock = new object();

	private readonly object _fovTablePatchLock = new object();

	private readonly object _valueEncryptionPatchLock = new object();

	private readonly object _xpBackingLock = new object();

	private List<LiveProfileIntegerMatch> _xpBackingMatches = new List<LiveProfileIntegerMatch>();

	private System.Threading.Timer _xpValueGuardTimer;

	private int _xpValueGuardRunning;

	private int _xpValueGuardValue;

	private int _xpValueGuardTicks;

	private ulong _valueEncryptionPatchAddress;

	private byte[] _valueEncryptionPatchOriginal;

	private bool _valueEncryptionPatchOwned;

	private IntPtr _handle;

	private ulong _mainBase;

	private int _mainSize;

	private ulong _crcFunctionPointerAddress;

	private ulong _crcOriginalPointer;

	private ulong _crcRetAddress;

	private bool _crcBypassActive;

	private System.Threading.Timer _crcTimer;

	private int _crcTimerRunning;

	private System.Threading.Timer _superBrakeGuardTimer;

	private RuntimeDetour _superBrakeGuardDetour;

	private RuntimeProfileHookDescriptor _superBrakeGuardDescriptor;

	private int _superBrakeGuardRunning;

	private bool _superBrakeGuardLastState;

	private System.Threading.Timer _jumpGuardTimer;

	private RuntimeDetour _jumpGuardDetour;

	private RuntimeProfileHookDescriptor _jumpGuardDescriptor;

	private int _jumpGuardRunning;

	private bool _jumpGuardLastState;

	private int _jumpGuardVirtualKey;

	private long _jumpGuardNextPulseUtcTicks;

	private System.Threading.Timer _boostGuardTimer;

	private RuntimeDetour _boostGuardDetour;

	private RuntimeProfileHookDescriptor _boostGuardDescriptor;

	private int _boostGuardRunning;

	private int _boostGuardVirtualKey;

	private System.Threading.Timer _driftModeGuardTimer;

	private RuntimeDetour _driftModeGuardDetour;

	private RuntimeProfileHookDescriptor _driftModeGuardDescriptor;

	private int _driftModeGuardRunning;

	private int _driftModeGuardVirtualKey;

	private int _driftModeGuardValue;

	private System.Threading.Timer _airControlGuardTimer;

	private RuntimeDetour _airControlGuardDetour;

	private RuntimeProfileHookDescriptor _airControlGuardDescriptor;

	private int _airControlGuardRunning;

	private int _airControlGuardVirtualKey;

	private float _airControlStrength;

	private long _airControlNextPulseUtcTicks;

	private System.Threading.Timer _noClipGuardTimer;

	private RuntimeDetour _noClipGuardDetour;

	private int _noClipGuardRunning;

	private int _noClipGuardVirtualKey;

	private ulong _noClipLastVehiclePointer;

	private float _noClipLastDirX;

	private float _noClipLastDirZ;

	private float _noClipLastSpeed;

	private float _noClipLastPosX;

	private float _noClipLastPosZ;

	private long _noClipLastDirectionTicks;

	private bool _noClipDirectionCaptured;

	private System.Threading.Timer _teleportToWaypointGuardTimer;

	private RuntimeDetour _teleportVehicleDetour;

	private RuntimeDetour _teleportWaypointDetour;

	private RuntimeProfileHookDescriptor _teleportWaypointDescriptor;

	private List<RuntimeDetour> _teleportWaypointCopyDetours = new List<RuntimeDetour>();

	private List<RuntimeProfileHookDescriptor> _teleportWaypointCopyDescriptors = new List<RuntimeProfileHookDescriptor>();

	private int _teleportToWaypointGuardRunning;

	private int _teleportVirtualKey;

	private bool _teleportKeyLastState;

	private long _teleportCooldownUntilUtcTicks;

	private byte[] _teleportRepeatPosition;

	private long _teleportRepeatUntilUtcTicks;

	private string _teleportLastSource = string.Empty;

	private byte[] _teleportSavedPosition;

	private string _teleportSavedName = string.Empty;

	private bool _vehicleAccelerationEnabled;

	private int _vehicleAccelerationValue;

	private bool _vehicleBoostEnabled;

	private int _vehicleBoostValue;

	private bool _vehicleSuperBrakeEnabled;

	private bool _vehicleAdaptiveBrakeEnabled;

	private int _vehicleAdaptiveBrakeValue;

	private int _brakeVirtualKey = 83;

	private long _brakePressedSinceUtcTicks;

	private static readonly byte[] TimeAttackRecordNeedle = new byte[20]
	{
		6, 0, 0, 0, 2, 0, 0, 0, 6, 0,
		0, 0, 2, 0, 0, 0, 87, 0, 0, 0
	};

	private static readonly ProfileIntegerHookLayout ProfileIntegerFieldsLayout = BuildProfileIntegerFieldsLayout();

	private static readonly XpAggregateHookLayout XpAggregateLayout = BuildXpAggregateLayout();

	private static readonly byte[] GravityAllAxesOriginal = new byte[112]
	{
		243, 15, 16, 79, 4, 15, 40, 193, 243, 15,
		89, 75, 8, 243, 15, 89, 67, 4, 243, 15,
		17, 67, 4, 243, 15, 17, 75, 8, 243, 15,
		16, 79, 4, 15, 40, 193, 243, 15, 89, 75,
		16, 243, 15, 89, 67, 20, 243, 15, 17, 75,
		16, 243, 15, 17, 67, 20, 243, 15, 16, 87,
		4, 15, 40, 194, 243, 15, 89, 83, 28, 243,
		15, 89, 67, 32, 243, 15, 17, 83, 28, 243,
		15, 17, 67, 32, 243, 15, 16, 79, 4, 15,
		40, 193, 243, 15, 89, 75, 40, 243, 15, 89,
		67, 44, 243, 15, 17, 75, 40, 243, 15, 17,
		67, 44
	};


    private ulong _seasonEntityGlobalAddr;
    private bool _seasonResolved;
    private const int SeasonValueOffset = 0x278;

    public enum FHSeason
    {
        Spring = 0,
        Summer = 1,
        Autumn = 2,
        Winter = 3,
    }

    public bool SetSeason(FHSeason season)
    {
        if (!IsAlive)
            throw new InvalidOperationException("Not attached.");

        if (!_seasonResolved)
        {
            if (!ResolveSeasonEntity(out var error))
            {
                _log("Season: " + error);
                return false;
            }
        }

        ulong entityPtr = method_0(_seasonEntityGlobalAddr);
        if (entityPtr == 0)
        {
            _log("Season: entity pointer is null — game may not be fully loaded.");
            return false;
        }

        ulong seasonAddr = entityPtr + SeasonValueOffset;
        int current = method_1(seasonAddr);

        if (current == (int)season)
        {
            _log("Season already set to " + season + ".");
            return true;
        }

        method_2(seasonAddr, (int)season);
        _log("Season changed: " + SeasonName(current) + " (" + current + ") -> " +
             season + " (" + (int)season + ")");

        // Nudge visual update flags at +0x2D8..+0x2DA
        NudgeSeasonVisualUpdate(entityPtr);
        return true;
    }

    public int GetCurrentSeason() => GetCurrentSeason(autoResolve: false);

    public int GetCurrentSeason(bool autoResolve)
    {
        if (!IsAlive) return -1;
        if (!_seasonResolved)
        {
            if (!autoResolve) return -1;
            if (!ResolveSeasonEntity(out _)) return -1;
        }
        ulong entityPtr = method_0(_seasonEntityGlobalAddr);
        if (entityPtr == 0) return -1;
        return method_1(entityPtr + SeasonValueOffset);
    }

    private bool ResolveSeasonEntity(out string error)
    {
        error = null;
        if (_mainBase == 0 || _mainSize <= 0)
        {
            error = "Main module not captured.";
            return false;
        }

        byte[] module = ReadBytes(_mainBase, _mainSize);
        if (module.Length == 0)
        {
            error = "Could not read main module.";
            return false;
        }

        // Primary signature: MOV RCX,[rip+disp] / CALL / TEST AL,AL / JNZ +0F /
        //                    LEA RDX,["SeasonSettings Loaded"] / MOV RCX,RDI
        string[] sigs = {
        "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 75 0F 48 8D 15 ?? ?? ?? ?? 48 8B CF",
        "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B CF E8",
    };

        foreach (string sig in sigs)
        {
            int[] pattern = Pattern.Parse(sig);
            foreach (int off in Pattern.FindAll(module, pattern, 4))
            {
                ulong matchAddr = _mainBase + (ulong)off;

                // Read disp32 from MOV RCX,[rip+disp32] at off+3
                int disp = BitConverter.ToInt32(module, off + 3);

                // global = matchAddr + 7 (instr len) + disp
                ulong globalAddr = (ulong)((long)(matchAddr + 7) + disp);

                ulong entityPtr = method_0(globalAddr);
                if (entityPtr != 0)
                {
                    int season = method_1(entityPtr + SeasonValueOffset);
                    if (season < 0 || season > 3)
                    {
                        _log("Season: value at entity+0x278 = " + season +
                             " (out of range), skipping candidate.");
                        continue;
                    }
                }

                _seasonEntityGlobalAddr = globalAddr;
                _seasonResolved = true;
                _log("Season entity resolved: global=0x" + globalAddr.ToString("X") +
                     ", entity=0x" + entityPtr.ToString("X") +
                     ", currentSeason=" + SeasonName(method_1(entityPtr + SeasonValueOffset)));
                return true;
            }
        }

        error = "Season entity AOB signature was not found.";
        return false;
    }

    private void NudgeSeasonVisualUpdate(ulong entityPtr)
    {
        for (ulong off = 0x2D8; off <= 0x2DA; off++)
        {
            try
            {
                byte[] current = ReadBytes(entityPtr + off, 1);
                if (current.Length > 0 && current[0] == 0)
                {
                    WriteByte(entityPtr + off, 1);
                    _log("Season: set visual flag at entity+0x" + off.ToString("X"));
                }
            }
            catch { /* flag offsets may vary between builds */ }
        }
    }

    public static string SeasonName(int season) => season switch
    {
        0 => "Spring",
        1 => "Summer",
        2 => "Autumn",
        3 => "Winter",
        _ => "Unknown(" + season + ")",
    };


    private static readonly GravityHookLayout GravityAllAxesLayout = BuildGravityAllAxesLayout();

	private static readonly SimpleToggleHookLayout NoWaterDragLayout = BuildNoWaterDragLayout();

	private static readonly VehicleControlHookLayout VehicleControlLayout = BuildVehicleControlLayout();

	public ulong DatabaseObject { get; private set; }

	public ulong QueryFunction { get; private set; }

	public int CandidateCount => _candidates.Count;

	public bool IsAlive
	{
		get
		{
			if (_process != null && !_process.HasExited)
			{
				return _handle != IntPtr.Zero;
			}
			return false;
		}
	}

	public RemoteDatabase(Process process, Action<string> log)
	{
		_process = process;
		_log = log;
	}

	public void Attach()
	{
		_handle = Native.OpenProcess(2035711u, bInheritHandle: false, (uint)_process.Id);
		if (_handle == IntPtr.Zero)
		{
			throw new InvalidOperationException("OpenProcess failed. Run as administrator.");
		}
		ProcessModule mainModule = _process.MainModule;
        ulong num = (ulong)(long)mainModule.BaseAddress.ToInt64();
        int moduleMemorySize = mainModule.ModuleMemorySize;
		_mainBase = num;
		_mainSize = moduleMemorySize;
		_log("Scanning main module: " + mainModule.ModuleName + " (" + moduleMemorySize + " bytes)");
		byte[] array = ReadBytes(num, moduleMemorySize);
		if (array.Length == 0)
		{
			throw new InvalidOperationException("Could not read main module memory.");
		}
		string[] array2 = new string[6] { "48 8B 0D ? ? ? ? 48 8B 01 4C 8D 45 ? 48 8D 55 ? FF 50 48 90 48 8B 4D ? 48 85 C9", "0F 84 ? ? ? ? 48 8B 35 ? ? ? ? 48 85 F6 74", "0F 85 ? ? ? ? 48 8B 35 ? ? ? ? 48 85 F6 74", "48 8B 35 ? ? ? ? 48 85 F6 74", "48 8B 35 ? ? ? ? 48 85 F6 0F 84", "48 8B 35 ? ? ? ? 48 85 F6 0F 85" };
		List<DatabaseCandidate> list = new List<DatabaseCandidate>();
		string[] array3 = array2;
		foreach (string text in array3)
		{
			int[] pattern = Pattern.Parse(text);
			foreach (int item in Pattern.FindAll(array, pattern, 64))
			{
				DatabaseCandidate candidate = TryBuildCandidate(array, num, item);
				if (candidate.Valid && !list.Any((DatabaseCandidate c) => c.DatabaseObject == candidate.DatabaseObject && c.QueryFunction == candidate.QueryFunction))
				{
					list.Add(candidate);
					_log("Candidate " + list.Count + " at 0x" + candidate.MatchAddress.ToString("X") + " db=0x" + candidate.DatabaseObject.ToString("X") + " fn=0x" + candidate.QueryFunction.ToString("X") + " via " + text);
				}
			}
			if (list.Count > 0)
			{
				break;
			}
		}
		if (list.Count == 0)
		{
			throw new InvalidOperationException("Database signature not found. If FH6 updated, the AOB pattern needs a refresh.");
		}
		DatabaseCandidate databaseCandidate = list[0];
		_candidates.Clear();
		_candidates.AddRange(list);
		DatabaseObject = databaseCandidate.DatabaseObject;
		QueryFunction = databaseCandidate.QueryFunction;
	}

	public void RestoreMemoryPatches()
	{
		StopXpValueGuard();
		StopTeleportToWaypointGuard();
		StopNoClipGuard();
		RestoreValueEncryptionBypass();
		StopCrcTimer();
		RestoreRuntimeProfileHooks();
		RestoreFovTablePatches();
		RestoreTimeAttackInfluencePatches();
		RestoreBestWheelspinOddsPatches();
		int num = 0;
		for (int num2 = _memoryPatches.Count - 1; num2 >= 0; num2--)
		{
			try
			{
				WriteProtectedBytes(_memoryPatches[num2].Address, _memoryPatches[num2].Original);
				num++;
			}
			catch (Exception ex)
			{
				_log("Could not restore runtime patch at 0x" + _memoryPatches[num2].Address.ToString("X") + ": " + ex.Message);
			}
		}
		_memoryPatches.Clear();
		_log("Restored runtime query patches tracked by this process: " + num + ".");
		RestoreCrcPointer();
	}

	public void ApplyProfileRuntimeHook(RuntimeProfileFeature feature, int value, bool enabled)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		switch (feature)
		{
		case RuntimeProfileFeature.Gravity:
			ApplyGravityRuntimeHook(value, enabled);
			return;
		case RuntimeProfileFeature.FovSlider:
			ApplyFovTablePatch(value, enabled);
			return;
		case RuntimeProfileFeature.NoWaterDrag:
			if (enabled)
			{
				EnsureCrcBypass();
			}
			break;
		}
		if (feature == RuntimeProfileFeature.NoClip && enabled)
		{
			EnsureCrcBypass();
		}
		RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(feature);
		RuntimeDetour detour;
		switch (feature)
		{
		case RuntimeProfileFeature.NoClip:
			if (enabled)
			{
				RuntimeProfileHookDescriptor vehicleControlDescriptor = GetVehicleControlDescriptor(RuntimeProfileFeature.Jump);
				RuntimeDetour vehicleDetour = EnsureRuntimeProfileHook(vehicleControlDescriptor);
				StartNoClipGuard(vehicleDetour, 86);
			}
			else
			{
				StopNoClipGuard();
			}
			_log(profileHookDescriptor.Name + " " + (enabled ? "ON" : "OFF") + ".");
			return;
		case RuntimeProfileFeature.Acceleration:
			if (!enabled)
			{
				lock (_runtimePatchLock)
				{
					if (!_runtimeProfileHooks.TryGetValue(profileHookDescriptor.Key, out detour))
					{
						_vehicleAccelerationEnabled = false;
						_vehicleAccelerationValue = 0;
						_log(profileHookDescriptor.Name + " runtime hook is already OFF.");
						return;
					}
				}
			}
			else
			{
				detour = EnsureRuntimeProfileHook(profileHookDescriptor);
			}
			_vehicleAccelerationEnabled = enabled;
			_vehicleAccelerationValue = (enabled ? value : 0);
			ApplyVehicleControlLane(detour, profileHookDescriptor);
			_log("Acceleration " + (enabled ? "ON" : "OFF") + ".");
			return;
		case RuntimeProfileFeature.SuperBrake:
			_vehicleSuperBrakeEnabled = enabled;
			if (enabled)
			{
				detour = EnsureRuntimeProfileHook(profileHookDescriptor);
				StartSuperBrakeGuard(detour, profileHookDescriptor);
				_log("Super Brake ON. Key=" + ((Keys)_brakeVirtualKey).ToString() + " or controller LT/LB. First second is instant stop, then reverse is allowed.");
				return;
			}
			if (_vehicleAdaptiveBrakeEnabled)
			{
				ApplyVehicleControlLaneIfPresent(profileHookDescriptor);
			}
			else
			{
				StopSuperBrakeGuard();
			}
			_log("Super Brake OFF.");
			return;
		case RuntimeProfileFeature.AdaptiveBrake:
			_vehicleAdaptiveBrakeEnabled = enabled;
			_vehicleAdaptiveBrakeValue = (enabled ? value : 0);
			if (enabled)
			{
				detour = EnsureRuntimeProfileHook(profileHookDescriptor);
				StartSuperBrakeGuard(detour, profileHookDescriptor);
				_log("Adaptive Brake ON. Hold keyboard brake or controller LT/LB.");
				return;
			}
			if (_vehicleSuperBrakeEnabled)
			{
				ApplyVehicleControlLaneIfPresent(profileHookDescriptor);
			}
			else
			{
				StopSuperBrakeGuard();
			}
			_log("Adaptive Brake OFF.");
			return;
		case RuntimeProfileFeature.AirControl:
		{
			float num = (enabled ? BitConverter.ToSingle(BitConverter.GetBytes(value), 0) : 0f);
			if (enabled)
			{
				if (float.IsNaN(num) || float.IsInfinity(num) || num < 0f || !(num <= 0.95f))
				{
					throw new InvalidOperationException("Air Control strength must be between 0 and 0.95.");
				}
				detour = EnsureRuntimeProfileHook(profileHookDescriptor);
				StartAirControlGuard(detour, profileHookDescriptor, 78, num);
				_log("Air Control ON. Hold W/up or controller forward while airborne for straight horizontal pulses.");
			}
			else
			{
				StopAirControlGuard();
				_log("Air Control OFF.");
			}
			return;
		}
		case RuntimeProfileFeature.FreezeAI:
			if (!enabled)
			{
				lock (_runtimePatchLock)
				{
					if (!_runtimeProfileHooks.TryGetValue(profileHookDescriptor.Key, out detour))
					{
						_log(profileHookDescriptor.Name + " runtime hook is already OFF.");
						return;
					}
				}
			}
			else
			{
				RuntimeProfileHookDescriptor vehicleControlDescriptor2 = GetVehicleControlDescriptor(RuntimeProfileFeature.Jump);
				RuntimeDetour runtimeDetour = EnsureRuntimeProfileHook(vehicleControlDescriptor2);
				detour = EnsureRuntimeProfileHook(profileHookDescriptor);
				if (profileHookDescriptor.ObjectPointerOffset >= 0)
				{
					ulong value2 = runtimeDetour.DetourAddress + (ulong)VehicleControlLayout.VehiclePointerOffset;
					method_3(detour.DetourAddress + (ulong)profileHookDescriptor.ObjectPointerOffset, value2);
				}
			}
			WriteByte(detour.DetourAddress + (ulong)profileHookDescriptor.ToggleOffset, (byte)(enabled ? 1 : 0));
			_log(profileHookDescriptor.Name + " " + (enabled ? "ON" : "OFF") + ".");
			return;
		case RuntimeProfileFeature.DangerSignDistance:
		case RuntimeProfileFeature.SpeedTrapMultiplier:
		case RuntimeProfileFeature.TimeOfDay:
		case RuntimeProfileFeature.SeriesPoints:
			ApplyProfileRuntimeHookGroup(feature, value, enabled);
			return;
		}
		if (!enabled)
		{
			lock (_runtimePatchLock)
			{
				if (!_runtimeProfileHooks.TryGetValue(profileHookDescriptor.Key, out detour))
				{
					_log(profileHookDescriptor.Name + " runtime hook is already OFF.");
					return;
				}
			}
		}
		else
		{
			detour = EnsureRuntimeProfileHook(profileHookDescriptor);
		}
		if (profileHookDescriptor.ValueOffset >= 0)
		{
			method_2(detour.DetourAddress + (ulong)profileHookDescriptor.ValueOffset, value);
		}
		WriteByte(detour.DetourAddress + (ulong)profileHookDescriptor.ToggleOffset, (byte)(enabled ? 1 : 0));
		if (profileHookDescriptor.ResetByteOffset >= 0 && enabled)
		{
			WriteByte(detour.DetourAddress + (ulong)profileHookDescriptor.ResetByteOffset, 0);
		}
		if (enabled)
		{
			TryWriteCapturedRuntimeObjectValue(detour, profileHookDescriptor, value);
		}
		_log(profileHookDescriptor.Name + " " + (enabled ? "ON" : "OFF") + ".");
	}

	private void ApplyProfileRuntimeHookGroup(RuntimeProfileFeature feature, int value, bool enabled)
	{
		int num = 0;
		int num2 = 0;
		string text = null;
		RuntimeProfileHookDescriptor[] profileHookDescriptors = GetProfileHookDescriptors(feature);
		foreach (RuntimeProfileHookDescriptor runtimeProfileHookDescriptor in profileHookDescriptors)
		{
			try
			{
				RuntimeDetour value2;
				if (!enabled)
				{
					lock (_runtimePatchLock)
					{
						if (!_runtimeProfileHooks.TryGetValue(runtimeProfileHookDescriptor.Key, out value2))
						{
							continue;
						}
					}
				}
				else
				{
					value2 = EnsureRuntimeProfileHook(runtimeProfileHookDescriptor);
				}
				if (runtimeProfileHookDescriptor.ValueOffset >= 0)
				{
					method_2(value2.DetourAddress + (ulong)runtimeProfileHookDescriptor.ValueOffset, value);
				}
				WriteByte(value2.DetourAddress + (ulong)runtimeProfileHookDescriptor.ToggleOffset, (byte)(enabled ? 1 : 0));
				if (enabled)
				{
					TryWriteCapturedRuntimeObjectValue(value2, runtimeProfileHookDescriptor, value);
				}
				num++;
			}
			catch (Exception ex)
			{
				num2++;
				if (text == null)
				{
					text = runtimeProfileHookDescriptor.Key + ": " + ex.Message;
				}
			}
		}
		string runtimeFeatureName = GetRuntimeFeatureName(feature);
		if (num == 0)
		{
			if (enabled && text != null)
			{
				throw new InvalidOperationException(runtimeFeatureName + " hook could not be applied. " + text);
			}
			_log(runtimeFeatureName + " runtime hook is already OFF.");
		}
		else
		{
			_log(runtimeFeatureName + " " + (enabled ? "ON" : "OFF") + ((num2 > 0) ? (" (" + num + " path(s), " + num2 + " optional path(s) skipped).") : "."));
		}
	}

	private bool TryWriteCapturedRuntimeObjectValue(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor, int value)
	{
		if (detour != null && descriptor != null && descriptor.ObjectPointerOffset >= 0 && descriptor.ObjectValueFieldOffset >= 0)
		{
			ulong num = method_0(detour.DetourAddress + (ulong)descriptor.ObjectPointerOffset);
			if (num == 0L)
			{
				return false;
			}
			ulong address = num + (ulong)descriptor.ObjectValueFieldOffset;
			if (!IsWritableMemoryRange(address, 4))
			{
				return false;
			}
			method_2(address, value);
			return true;
		}
		return false;
	}

	private void ApplyFovTablePatch(int value, bool enabled)
	{
		lock (_fovTablePatchLock)
		{
			if (!enabled)
			{
				RestoreFovTablePatches(log: true);
				return;
			}
			EnsureCrcBypass();
			RestoreFovTablePatches(log: false);
			float num = BitConverter.ToSingle(BitConverter.GetBytes(value), 0);
			if (float.IsNaN(num) || float.IsInfinity(num))
			{
				num = 0.7f;
			}
			float num2 = Math.Max(0f, Math.Min(10f, num * 10f));
			float num3 = (num2 - 7f) * 4f;
			List<FovTableTarget> list = FindFovTableTargets();
			int num4 = 0;
			foreach (FovTableTarget item in list)
			{
				byte[] array = ReadBytes(item.Address, 4);
				if (array.Length >= 4)
				{
					float num5 = BitConverter.ToSingle(array, 0);
					if (!float.IsNaN(num5) && !float.IsInfinity(num5))
					{
						float value2 = Math.Max(5f, Math.Min(130f, num5 + num3));
						WriteProtectedBytes(item.Address, BitConverter.GetBytes(value2));
						_fovTablePatches.Add(new MemoryPatch
						{
							Address = item.Address,
							Original = array
						});
						num4++;
					}
				}
			}
			if (num4 == 0)
			{
				throw new InvalidOperationException("FOV camera tables were found, but no writable FOV values were patched.");
			}
			_log("FOV Slider ON with value " + num2.ToString("0.#", CultureInfo.InvariantCulture) + "/10. Camera table values patched: " + num4.ToString(CultureInfo.InvariantCulture) + ".");
		}
	}

	private void RestoreFovTablePatches()
	{
		RestoreFovTablePatches(log: true);
	}

	private void RestoreFovTablePatches(bool log)
	{
		lock (_fovTablePatchLock)
		{
			int num = 0;
			for (int num2 = _fovTablePatches.Count - 1; num2 >= 0; num2--)
			{
				try
				{
					WriteProtectedBytes(_fovTablePatches[num2].Address, _fovTablePatches[num2].Original);
					num++;
				}
				catch (Exception ex)
				{
					_log("Could not restore FOV value at 0x" + _fovTablePatches[num2].Address.ToString("X") + ": " + ex.Message);
				}
			}
			_fovTablePatches.Clear();
			if (log)
			{
				_log((num > 0) ? ("FOV Slider OFF. Restored " + num.ToString(CultureInfo.InvariantCulture) + " camera table value(s).") : "FOV Slider is already OFF.");
			}
		}
	}

	private List<FovTableTarget> FindFovTableTargets()
	{
		byte[] array = ReadBytes(_mainBase, _mainSize);
		if (array.Length == 0)
		{
			throw new InvalidOperationException("Could not read main module memory for FOV table scan.");
		}
		List<int> list = Pattern.FindAll(array, Pattern.Parse("90 40 CD CC 8C 40 1F 85 2B 3F 00 00 00 40"), 4).ToList();
		List<int> list2 = Pattern.FindAll(array, Pattern.Parse("CD CC 4C 3E 00 50 43 47 00 00 34 42 00 00 20"), 4).ToList();
		List<int> list3 = Pattern.FindAll(array, Pattern.Parse("CD ? 4C 3E ? ? ? 47 00 ? 34 ? 00 00 20 42 ? 00 A0"), 2).ToList();
		if (list.Count >= 2 && list2.Count >= 2 && list3.Count >= 1)
		{
			List<FovTableTarget> list4 = new List<FovTableTarget>();
			HashSet<ulong> seen = new HashSet<ulong>();
			ulong num = _mainBase + (ulong)list[0];
			ulong num2 = _mainBase + (ulong)list[list.Count - 1];
			ulong num3 = _mainBase + (ulong)list2[0];
			ulong num4 = _mainBase + (ulong)list2[list2.Count - 1];
			ulong num5 = (ulong)((long)_mainBase + (long)list3[0] - 32L);
			AddFovTableTarget(list4, seen, "Chase Min", num - 10L);
			AddFovTableTarget(list4, seen, "Chase Max", num - 6L);
			AddFovTableTarget(list4, seen, "Far Chase Min", num2 - 10L);
			AddFovTableTarget(list4, seen, "Far Chase Max", num2 - 6L);
			AddFovTableTarget(list4, seen, "Driver Min", num5 - 4L);
			AddFovTableTarget(list4, seen, "Driver Max", num5);
			AddFovTableTarget(list4, seen, "Bumper Min", num3 - 36L);
			AddFovTableTarget(list4, seen, "Bumper Max", num3 - 32L);
			AddFovTableTarget(list4, seen, "Hood Min", num4 - 36L);
			AddFovTableTarget(list4, seen, "Hood Max", num4 - 32L);
			if (list4.Count == 0)
			{
				throw new InvalidOperationException("FOV table signatures matched, but no valid float targets were readable.");
			}
			return list4;
		}
		throw new InvalidOperationException("FOV table signatures did not match this FH6 build. Chase=" + list.Count.ToString(CultureInfo.InvariantCulture) + ", camera=" + list2.Count.ToString(CultureInfo.InvariantCulture) + ", driver=" + list3.Count.ToString(CultureInfo.InvariantCulture) + ".");
	}

	private void AddFovTableTarget(List<FovTableTarget> targets, HashSet<ulong> seen, string name, ulong address)
	{
		if (!seen.Contains(address) && IsReadableMemoryRange(address, 4))
		{
			float num = ReadFloat(address);
			if (!float.IsNaN(num) && !float.IsInfinity(num) && !(num < 5f) && num <= 130f)
			{
				seen.Add(address);
				targets.Add(new FovTableTarget
				{
					Name = name,
					Address = address
				});
			}
		}
	}

	private static string GetRuntimeFeatureName(RuntimeProfileFeature feature)
	{
		return feature switch
		{
			RuntimeProfileFeature.SeriesPoints => "Series Points", 
			RuntimeProfileFeature.TimeOfDay => "Time of Day", 
			RuntimeProfileFeature.SpeedZoneSpeed => "Speed Zone Multiplier", 
			RuntimeProfileFeature.DangerSignDistance => "Danger Sign Multiplier", 
			RuntimeProfileFeature.SpeedTrapMultiplier => "Speed Trap Multiplier", 
			RuntimeProfileFeature.FovSlider => "FOV Slider", 
			RuntimeProfileFeature.FreezeAI => "Freeze AI", 
			RuntimeProfileFeature.NoClip => "No Clip", 
			_ => feature.ToString(), 
		};
	}

	private void EnsureValueEncryptionBypass()
	{
		lock (_valueEncryptionPatchLock)
		{
			if (_valueEncryptionPatchAddress == 0L)
			{
				EnsureCrcBypass();
				byte[] array = ReadBytes(_mainBase, _mainSize);
				if (array.Length == 0)
				{
					throw new InvalidOperationException("Could not read main module memory for Value Encryption bypass scan.");
				}
				int[] pattern = Pattern.Parse("48 8B ? 48 89 ? ? 48 89 ? ? 48 89 ? ? 55 41 ? 41 ? 48 8D ? ? 48 81 EC ? ? ? ? 48 8B ? ? ? ? ? 48 33 ? 48 89 ? ? 4C 8B ? 48 89");
				List<int> list = Pattern.FindAll(array, pattern, 3).ToList();
				if (list.Count == 0)
				{
					throw new InvalidOperationException("Value Encryption bypass signature was not found.");
				}
				if (list.Count > 1)
				{
					throw new InvalidOperationException("Value Encryption bypass signature was not unique.");
				}
				ulong num = _mainBase + (ulong)list[0];
				byte[] array2 = ReadBytes(num, 3);
				if (array2.Length < 3)
				{
					throw new InvalidOperationException("Could not read Value Encryption bytes.");
				}
				_valueEncryptionPatchAddress = num;
				if (array2[0] == 195)
				{
					_valueEncryptionPatchOriginal = null;
					_valueEncryptionPatchOwned = false;
					_log("XP Value save bypass is already active from another tool.");
				}
				else
				{
					_valueEncryptionPatchOriginal = array2;
					_valueEncryptionPatchOwned = true;
					WriteProtectedBytes(num, BuildValueEncryptionBypassPatch(_valueEncryptionPatchOriginal.Length));
					_log("XP Value save bypass ON.");
				}
			}
		}
	}

	private void RestoreValueEncryptionBypass()
	{
		lock (_valueEncryptionPatchLock)
		{
			if (_valueEncryptionPatchAddress == 0L)
			{
				return;
			}
			if (_valueEncryptionPatchOwned && _valueEncryptionPatchOriginal != null && _valueEncryptionPatchOriginal.Length > 0)
			{
				try
				{
					WriteProtectedBytes(_valueEncryptionPatchAddress, _valueEncryptionPatchOriginal);
					_log("XP Value save bypass OFF.");
				}
				catch (Exception ex)
				{
					_log("Could not restore XP Value save bypass: " + ex.Message);
				}
			}
			_valueEncryptionPatchAddress = 0uL;
			_valueEncryptionPatchOriginal = null;
			_valueEncryptionPatchOwned = false;
		}
	}

	private static byte[] BuildValueEncryptionBypassPatch(int length)
	{
		byte[] array = new byte[Math.Max(1, length)];
		array[0] = 195;
		for (int i = 1; i < array.Length; i++)
		{
			array[i] = 144;
		}
		return array;
	}

	private void RestoreValueEncryptionBypassForCleanWindow()
	{
		lock (_valueEncryptionPatchLock)
		{
			if (_valueEncryptionPatchAddress != 0L && _valueEncryptionPatchOwned && _valueEncryptionPatchOriginal != null && _valueEncryptionPatchOriginal.Length != 0)
			{
				WriteProtectedBytes(_valueEncryptionPatchAddress, _valueEncryptionPatchOriginal);
			}
		}
	}

	private void ReapplyValueEncryptionBypassForCleanWindow()
	{
		lock (_valueEncryptionPatchLock)
		{
			if (_valueEncryptionPatchAddress != 0L && _valueEncryptionPatchOwned && _valueEncryptionPatchOriginal != null && _valueEncryptionPatchOriginal.Length != 0)
			{
				WriteProtectedBytes(_valueEncryptionPatchAddress, BuildValueEncryptionBypassPatch(_valueEncryptionPatchOriginal.Length));
			}
		}
	}

	private void StartXpValueGuard(int value)
	{
		StartXpValueGuard(value, refreshOnFirstTick: true);
	}

	private void StartXpValueGuard(int value, bool refreshOnFirstTick)
	{
		_xpValueGuardValue = value;
		_xpValueGuardTicks = ((!refreshOnFirstTick) ? 1 : 0);
		if (_xpValueGuardTimer == null)
		{
			_xpValueGuardTimer = new System.Threading.Timer(XpValueGuardTick, null, 250, 250);
		}
		else
		{
			_xpValueGuardTimer.Change(250, 250);
		}
		_log("XP Value fast guard ON.");
	}

	private void StopXpValueGuard()
	{
		System.Threading.Timer xpValueGuardTimer = _xpValueGuardTimer;
		_xpValueGuardTimer = null;
		xpValueGuardTimer?.Dispose();
		_xpValueGuardRunning = 0;
		_xpValueGuardTicks = 0;
		if (xpValueGuardTimer != null)
		{
			_log("XP Value fast guard OFF.");
		}
	}

	private void XpValueGuardTick(object state)
	{
		if (Interlocked.Exchange(ref _xpValueGuardRunning, 1) == 1)
		{
			return;
		}
		try
		{
			if (!IsAlive)
			{
				StopXpValueGuard();
				return;
			}
			int num = Interlocked.Increment(ref _xpValueGuardTicks);
			bool flag = num == 1 || num % 240 == 0;
			RuntimeProfileHookDescriptor xpAggregateDescriptor = GetXpAggregateDescriptor();
			RuntimeDetour value;
			lock (_runtimePatchLock)
			{
				_runtimeProfileHooks.TryGetValue(xpAggregateDescriptor.Key, out value);
			}
			if (value != null && value.DetourAddress != 0L)
			{
				method_2(value.DetourAddress + (ulong)xpAggregateDescriptor.ValueOffset, _xpValueGuardValue);
				WriteByte(value.DetourAddress + (ulong)xpAggregateDescriptor.ToggleOffset, 1);
				MaintainXpAggregateObject(value, xpAggregateDescriptor, _xpValueGuardValue);
			}
			if (!HasXpBackingMatches() && !flag)
			{
				return;
			}
			try
			{
				MaintainLiveProfileXpLevel(_xpValueGuardValue, flag);
			}
			catch (Exception ex)
			{
				if (flag)
				{
					_log("XP Value guard is waiting for live profile fields: " + ex.Message);
				}
			}
		}
		catch (Exception ex2)
		{
			_log("XP Value fast guard stopped: " + ex2.Message);
			if (!IsAlive)
			{
				StopXpValueGuard();
			}
		}
		finally
		{
			Interlocked.Exchange(ref _xpValueGuardRunning, 0);
		}
	}

	private int MaintainXpAggregateObject(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor, int value)
	{
		if (detour != null && descriptor != null && descriptor.ObjectPointerOffset >= 0)
		{
			ulong num = method_0(detour.DetourAddress + (ulong)descriptor.ObjectPointerOffset);
			if (num == 0L)
			{
				return 0;
			}
			ulong address = num + 136L;
			ulong address2 = num + 140L;
			if (!IsWritableMemoryRange(address, 8))
			{
				return 0;
			}
			method_2(address2, value);
			method_2(address, 0);
			return 1;
		}
		return 0;
	}

	private bool HasXpBackingMatches()
	{
		lock (_xpBackingLock)
		{
			return _xpBackingMatches.Count > 0;
		}
	}

	public void SetBrakeVirtualKey(int virtualKey)
	{
		if (virtualKey <= 0)
		{
			throw new InvalidOperationException("Brake keybind is not valid.");
		}
		_brakeVirtualKey = virtualKey;
	}

    /// <summary>Starts the fast XP guard timer — called from the UI layer.</summary>
    public void StartXpValueGuard_Public(int value) => StartXpValueGuard(value);

    /// <summary>Stops the fast XP guard timer — called from the UI layer.</summary>
    public void StopXpValueGuard_Public() => StopXpValueGuard();

    public void VerifyRuntimeFeatureHook(RuntimeProfileFeature feature)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		if (_mainBase != 0L && _mainSize > 0)
		{
			RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(feature);
			lock (_runtimePatchLock)
			{
				if (_runtimeProfileHooks.TryGetValue(profileHookDescriptor.Key, out var value) && value != null && value.DetourAddress != 0L)
				{
					_log(profileHookDescriptor.Name + " hook is already installed at 0x" + value.Address.ToString("X") + ", detour=0x" + value.DetourAddress.ToString("X") + ".");
					return;
				}
			}
			byte[] array = ReadBytes(_mainBase, _mainSize);
			if (array.Length == 0)
			{
				throw new InvalidOperationException("Could not read main module memory for runtime hook scan.");
			}
			FindProfileHookTarget(array, profileHookDescriptor, out var hookAddress, out var current);
			_log(profileHookDescriptor.Name + " hook verified at 0x" + hookAddress.ToString("X") + ". Bytes: " + FormatBytes(current) + ".");
			return;
		}
		throw new InvalidOperationException("Main module was not captured during attach.");
	}

	public void VerifyVehicleControlRuntimeHook()
	{
		VerifyRuntimeFeatureHook(RuntimeProfileFeature.Acceleration);
	}

	private void ApplyGravityRuntimeHook(int encodedValue, bool enabled)
	{
		RuntimeProfileHookDescriptor gravityDescriptor = GetGravityDescriptor();
		if (!enabled)
		{
			DisableRuntimeHookLaneIfPresent(gravityDescriptor);
			DisableRuntimeHookLaneIfPresent(GetVehicleControlDescriptor(RuntimeProfileFeature.Gravity));
			_log("Gravity runtime hook OFF.");
			return;
		}
		float num = BitConverter.ToSingle(BitConverter.GetBytes(encodedValue), 0);
		if (!float.IsNaN(num) && !float.IsInfinity(num))
		{
			float stableGravityPhysicsScale = GetStableGravityPhysicsScale(num);
			float stableGravityVehicleForce = GetStableGravityVehicleForce(num);
			RuntimeDetour runtimeDetour = EnsureRuntimeProfileHook(gravityDescriptor);
			WriteByte(runtimeDetour.DetourAddress + (ulong)gravityDescriptor.ToggleOffset, 1);
			method_2(runtimeDetour.DetourAddress + (ulong)gravityDescriptor.ValueOffset, BitConverter.ToInt32(BitConverter.GetBytes(stableGravityPhysicsScale), 0));
			RuntimeProfileHookDescriptor vehicleControlDescriptor = GetVehicleControlDescriptor(RuntimeProfileFeature.Gravity);
			RuntimeDetour runtimeDetour2 = EnsureRuntimeProfileHook(vehicleControlDescriptor);
			method_2(runtimeDetour2.DetourAddress + (ulong)vehicleControlDescriptor.ValueOffset, BitConverter.ToInt32(BitConverter.GetBytes(stableGravityVehicleForce), 0));
			WriteByte(runtimeDetour2.DetourAddress + (ulong)vehicleControlDescriptor.ToggleOffset, (Math.Abs(stableGravityVehicleForce) > 0.0001f) ? ((byte)1) : ((byte)0));
			_log("Gravity runtime hook enabled. requested=" + FormatFloatInvariant(num * 100f) + "%, physics=x" + FormatFloatInvariant(stableGravityPhysicsScale) + ", vehicleForce=" + FormatFloatInvariant(stableGravityVehicleForce) + ".");
			return;
		}
		throw new InvalidOperationException("Gravity value is not valid.");
	}

	private void DisableRuntimeHookLaneIfPresent(RuntimeProfileHookDescriptor descriptor)
	{
		RuntimeDetour value;
		lock (_runtimePatchLock)
		{
			if (!_runtimeProfileHooks.TryGetValue(descriptor.Key, out value))
			{
				return;
			}
		}
		if (value != null && value.DetourAddress != 0L && !(_handle == IntPtr.Zero))
		{
			WriteByte(value.DetourAddress + (ulong)descriptor.ToggleOffset, 0);
			if (descriptor.ValueOffset >= 0)
			{
				method_2(value.DetourAddress + (ulong)descriptor.ValueOffset, 0);
			}
		}
	}

	private static float GetStableGravityPhysicsScale(float requestedScale)
	{
		if (requestedScale <= 0f)
		{
			return 0f;
		}
		if (requestedScale <= 1f)
		{
			return requestedScale;
		}
		return Math.Min(requestedScale, 2f);
	}

	private static float GetStableGravityVehicleForce(float requestedScale)
	{
		if (requestedScale > 1f)
		{
			return Math.Min((requestedScale - 1f) * 0.32f, 2.5f);
		}
		if (requestedScale < 0f)
		{
			return Math.Max(requestedScale * 0.15f, -1.5f);
		}
		return 0f;
	}

	public void SetJumpRuntimeHook(bool enabled, int virtualKey, float boost)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(RuntimeProfileFeature.Jump);
		if (!enabled)
		{
			StopJumpGuard();
			_log("Jump runtime hook OFF.");
			return;
		}
		if (virtualKey <= 0)
		{
			throw new InvalidOperationException("Jump keybind is not valid.");
		}
		if (float.IsNaN(boost) || float.IsInfinity(boost) || boost <= 0f)
		{
			throw new InvalidOperationException("Jump boost must be a positive number.");
		}
		RuntimeDetour runtimeDetour = EnsureRuntimeProfileHook(profileHookDescriptor);
		StartJumpGuard(runtimeDetour, profileHookDescriptor, virtualKey, boost);
		_log("Jump armed at detour 0x" + runtimeDetour.DetourAddress.ToString("X") + ". Tap for the old hop height, or hold the selected key for repeated controlled hops.");
	}

	public void SetBoostRuntimeHook(bool enabled, int virtualKey, float force)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(RuntimeProfileFeature.Boost);
		if (!enabled)
		{
			StopBoostGuard();
			_log("Boost runtime hook OFF.");
			return;
		}
		if (virtualKey <= 0)
		{
			throw new InvalidOperationException("Boost keybind is not valid.");
		}
		if (float.IsNaN(force) || float.IsInfinity(force) || force < -0.95f || force > 20f)
		{
			throw new InvalidOperationException("Boost amount must be between -0.95 and 20. Default is 0.02.");
		}
		RuntimeDetour detour = EnsureRuntimeProfileHook(profileHookDescriptor);
		StartBoostGuard(detour, profileHookDescriptor, virtualKey, force);
		_log("Boost armed. Hold key " + ((Keys)virtualKey).ToString() + " for nitro speed.");
	}

	public void SetAirControlRuntimeHook(bool enabled, int virtualKey, float strength)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(RuntimeProfileFeature.AirControl);
		if (!enabled)
		{
			StopAirControlGuard();
			_log("Air Control runtime hook OFF.");
			return;
		}
		if (virtualKey <= 0)
		{
			throw new InvalidOperationException("Air Control keybind is not valid.");
		}
		if (float.IsNaN(strength) || float.IsInfinity(strength) || strength < 0f || strength > 0.95f)
		{
			throw new InvalidOperationException("Air Control amount must be between 0 and 0.95.");
		}
		RuntimeDetour detour = EnsureRuntimeProfileHook(profileHookDescriptor);
		StartAirControlGuard(detour, profileHookDescriptor, virtualKey, strength);
		_log("Air Control armed. Hold key " + ((Keys)virtualKey).ToString() + " with a direction while airborne.");
	}

	public void SetNoClipRuntimeHook(bool enabled, int virtualKey)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		if (!enabled)
		{
			StopNoClipGuard();
			_log("No Clip runtime hook OFF.");
			return;
		}
		if (virtualKey <= 0)
		{
			throw new InvalidOperationException("No Clip keybind is not valid.");
		}
		RuntimeProfileHookDescriptor vehicleControlDescriptor = GetVehicleControlDescriptor(RuntimeProfileFeature.Jump);
		RuntimeDetour vehicleDetour = EnsureRuntimeProfileHook(vehicleControlDescriptor);
		StartNoClipGuard(vehicleDetour, virtualKey);
		_log("No Clip armed. Hold key " + ((Keys)virtualKey).ToString() + " while driving into a wall.");
	}

	public void SetTeleportToWaypointRuntimeHook(bool enabled, int virtualKey)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		if (!enabled)
		{
			StopTeleportToWaypointGuard();
			_log("Teleport To Waypoint runtime hook OFF.");
			return;
		}
		if (virtualKey <= 0)
		{
			throw new InvalidOperationException("Teleport keybind is not valid.");
		}
		RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(RuntimeProfileFeature.Jump);
		RuntimeDetour vehicleDetour = EnsureRuntimeProfileHook(profileHookDescriptor);
		List<RuntimeDetour> list = new List<RuntimeDetour>();
		List<RuntimeProfileHookDescriptor> list2 = new List<RuntimeProfileHookDescriptor>();
		for (int i = 0; i < 4; i++)
		{
			try
			{
				RuntimeProfileHookDescriptor waypointDestinationCaptureDescriptor = GetWaypointDestinationCaptureDescriptor(i);
				RuntimeDetour item = EnsureRuntimeProfileHook(waypointDestinationCaptureDescriptor);
				list2.Add(waypointDestinationCaptureDescriptor);
				list.Add(item);
			}
			catch (Exception ex)
			{
				_log("Teleport waypoint capture " + (i + 1).ToString(CultureInfo.InvariantCulture) + " not ready: " + ex.Message);
			}
		}
		for (int j = 0; j < 3; j++)
		{
			try
			{
				RuntimeProfileHookDescriptor waypointRouteVectorDescriptor = GetWaypointRouteVectorDescriptor(j);
				RuntimeDetour item2 = EnsureRuntimeProfileHook(waypointRouteVectorDescriptor);
				list2.Add(waypointRouteVectorDescriptor);
				list.Add(item2);
			}
			catch (Exception ex2)
			{
				_log("Teleport route vector capture " + (j + 1).ToString(CultureInfo.InvariantCulture) + " not ready: " + ex2.Message);
			}
		}
		for (int k = 0; k < 2; k++)
		{
			try
			{
				RuntimeProfileHookDescriptor navigationDestinationPointerDescriptor = GetNavigationDestinationPointerDescriptor(k);
				RuntimeDetour item3 = EnsureRuntimeProfileHook(navigationDestinationPointerDescriptor);
				list2.Add(navigationDestinationPointerDescriptor);
				list.Add(item3);
			}
			catch (Exception ex3)
			{
				_log("Teleport navigation destination capture " + (k + 1).ToString(CultureInfo.InvariantCulture) + " not ready: " + ex3.Message);
			}
		}
		try
		{
			RuntimeProfileHookDescriptor satNavRouteObjectDescriptor = GetSatNavRouteObjectDescriptor();
			RuntimeDetour item4 = EnsureRuntimeProfileHook(satNavRouteObjectDescriptor);
			list2.Add(satNavRouteObjectDescriptor);
			list.Add(item4);
		}
		catch (Exception ex4)
		{
			_log("Teleport SatNav object capture not ready: " + ex4.Message);
		}
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = null;
		RuntimeDetour runtimeDetour = null;
		try
		{
			runtimeProfileHookDescriptor = GetCurrentDestinationPointerDescriptor();
			runtimeDetour = EnsureRuntimeProfileHook(runtimeProfileHookDescriptor);
		}
		catch (Exception ex5)
		{
			_log("Teleport current destination pointer capture not ready: " + ex5.Message);
		}
		if (list.Count == 0 && runtimeDetour == null)
		{
			throw new InvalidOperationException("Teleport waypoint capture hook was not found.");
		}
		StartTeleportToWaypointGuard(vehicleDetour, runtimeDetour, runtimeProfileHookDescriptor, list, list2, virtualKey);
		_log("Teleport To Waypoint armed. Set or refresh a waypoint, then press key " + ((Keys)virtualKey).ToString() + ".");
	}

	public byte[] ReadCurrentVehicleTeleportPosition()
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(RuntimeProfileFeature.Jump);
		RuntimeDetour vehicleDetour = EnsureRuntimeProfileHook(profileHookDescriptor);
		ulong num = ReadCurrentVehiclePointer(vehicleDetour);
		if (num == 0L)
		{
			throw new InvalidOperationException("Current vehicle was not captured yet. Sit in the car and move for a second, then try again.");
		}
		byte[] position = ReadBytes(num + 80L, 16);
		if (!IsValidTeleportPosition(position))
		{
			throw new InvalidOperationException("Current vehicle position did not look valid yet. Move the car a little and try again.");
		}
		return BuildTeleportVehiclePosition(num, position);
	}

	public void SetSavedLocationTeleportRuntimeHook(bool enabled, int virtualKey, byte[] position, string name)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		if (!enabled)
		{
			StopTeleportToWaypointGuard();
			_log("Saved Location Teleport runtime hook OFF.");
			return;
		}
		if (virtualKey <= 0)
		{
			throw new InvalidOperationException("Teleport keybind is not valid.");
		}
		if (!IsValidTeleportPosition(position))
		{
			throw new InvalidOperationException("Saved teleport location is not valid.");
		}
		RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(RuntimeProfileFeature.Jump);
		RuntimeDetour vehicleDetour = EnsureRuntimeProfileHook(profileHookDescriptor);
		StartSavedLocationTeleportGuard(vehicleDetour, virtualKey, position, name);
		_log("Saved Location Teleport armed. Press key " + ((Keys)virtualKey).ToString() + " for " + (string.IsNullOrWhiteSpace(name) ? "selected spot" : name) + ".");
	}

	public void TeleportToSavedLocationNow(byte[] position, string name)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		if (!IsValidTeleportPosition(position))
		{
			throw new InvalidOperationException("Saved teleport location is not valid.");
		}
		RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(RuntimeProfileFeature.Jump);
		RuntimeDetour vehicleDetour = EnsureRuntimeProfileHook(profileHookDescriptor);
		TeleportVehicleToSavedLocation(vehicleDetour, position, name);
	}

	public void SetDriftModeRuntimeHook(bool enabled, int virtualKey, float amount)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		RuntimeProfileHookDescriptor profileHookDescriptor = GetProfileHookDescriptor(RuntimeProfileFeature.DriftMode);
		if (!enabled)
		{
			StopDriftModeGuard();
			_log("Drift Mode runtime hook OFF.");
			return;
		}
		if (virtualKey <= 0)
		{
			throw new InvalidOperationException("Drift Mode keybind is not valid.");
		}
		if (float.IsNaN(amount) || float.IsInfinity(amount) || amount < -1f || amount > 1f)
		{
			throw new InvalidOperationException("Drift Mode amount must be between -1.0 and 1.0. Start around 0.035.");
		}
		RuntimeDetour detour = EnsureRuntimeProfileHook(profileHookDescriptor);
		StartDriftModeGuard(detour, profileHookDescriptor, virtualKey, amount);
		_log("Drift Mode armed. Hold key " + ((Keys)virtualKey).ToString() + " while turning to drift.");
	}

	private void StartSuperBrakeGuard(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor)
	{
		_superBrakeGuardDetour = detour;
		_superBrakeGuardDescriptor = descriptor;
		_brakePressedSinceUtcTicks = ((_superBrakeGuardLastState = IsBrakeInputPressed()) ? DateTime.UtcNow.Ticks : 0L);
		ApplyVehicleControlLane(detour, descriptor);
		if (_superBrakeGuardTimer == null)
		{
			_superBrakeGuardTimer = new System.Threading.Timer(SuperBrakeGuardTick, null, 0, 16);
		}
		else
		{
			_superBrakeGuardTimer.Change(0, 16);
		}
	}

	private void StopSuperBrakeGuard()
	{
		System.Threading.Timer superBrakeGuardTimer = _superBrakeGuardTimer;
		_superBrakeGuardTimer = null;
		superBrakeGuardTimer?.Dispose();
		RuntimeDetour superBrakeGuardDetour = _superBrakeGuardDetour;
		RuntimeProfileHookDescriptor superBrakeGuardDescriptor = _superBrakeGuardDescriptor;
		_superBrakeGuardDetour = null;
		_superBrakeGuardDescriptor = null;
		_superBrakeGuardLastState = false;
		_brakePressedSinceUtcTicks = 0L;
		if (superBrakeGuardDetour == null || superBrakeGuardDescriptor == null || superBrakeGuardDetour.DetourAddress == 0L || _handle == IntPtr.Zero)
		{
			return;
		}
		try
		{
			WriteByte(superBrakeGuardDetour.DetourAddress + (ulong)superBrakeGuardDescriptor.ToggleOffset, 0);
			if (superBrakeGuardDescriptor.ValueOffset >= 0)
			{
				method_2(superBrakeGuardDetour.DetourAddress + (ulong)superBrakeGuardDescriptor.ValueOffset, 0);
			}
		}
		catch
		{
		}
	}

	private void SuperBrakeGuardTick(object state)
	{
		if (Interlocked.Exchange(ref _superBrakeGuardRunning, 1) == 1)
		{
			return;
		}
		try
		{
			RuntimeDetour superBrakeGuardDetour = _superBrakeGuardDetour;
			RuntimeProfileHookDescriptor superBrakeGuardDescriptor = _superBrakeGuardDescriptor;
			if (superBrakeGuardDetour != null && superBrakeGuardDescriptor != null && superBrakeGuardDetour.DetourAddress != 0L && IsAlive)
			{
				ApplyVehicleControlLane(superBrakeGuardDetour, superBrakeGuardDescriptor);
			}
		}
		catch (Exception ex)
		{
			_log("Super Brake guard stopped: " + ex.Message);
			StopSuperBrakeGuard();
		}
		finally
		{
			Interlocked.Exchange(ref _superBrakeGuardRunning, 0);
		}
	}

	private void ApplyVehicleControlLaneIfPresent(RuntimeProfileHookDescriptor descriptor)
	{
		RuntimeDetour value;
		lock (_runtimePatchLock)
		{
			if (!_runtimeProfileHooks.TryGetValue(descriptor.Key, out value))
			{
				return;
			}
		}
		ApplyVehicleControlLane(value, descriptor);
	}

	private void ApplyVehicleControlLane(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor)
	{
		if (detour == null || descriptor == null || detour.DetourAddress == 0L)
		{
			return;
		}
		bool flag = (_vehicleSuperBrakeEnabled || _vehicleAdaptiveBrakeEnabled) && IsBrakeInputPressed();
		long ticks = DateTime.UtcNow.Ticks;
		if (flag)
		{
			if (!_superBrakeGuardLastState || _brakePressedSinceUtcTicks == 0L)
			{
				_brakePressedSinceUtcTicks = ticks;
			}
		}
		else
		{
			_brakePressedSinceUtcTicks = 0L;
		}
		_superBrakeGuardLastState = flag;
		int? num = null;
		if (flag)
		{
			long num2 = ((_brakePressedSinceUtcTicks == 0L) ? 0L : (ticks - _brakePressedSinceUtcTicks));
			num = ((_vehicleSuperBrakeEnabled && num2 < 10000000L) ? new int?(0) : ((!_vehicleAdaptiveBrakeEnabled) ? ((int?)null) : new int?(_vehicleAdaptiveBrakeValue)));
		}
		else if (_vehicleAccelerationEnabled)
		{
			num = _vehicleAccelerationValue;
		}
		if (!flag && _vehicleBoostEnabled && _boostGuardVirtualKey > 0 && IsKeyDown(_boostGuardVirtualKey))
		{
			num = _vehicleBoostValue;
		}
		if (num.HasValue)
		{
			method_2(detour.DetourAddress + (ulong)descriptor.ValueOffset, num.Value);
			WriteByte(detour.DetourAddress + (ulong)descriptor.ToggleOffset, 1);
		}
		else
		{
			WriteByte(detour.DetourAddress + (ulong)descriptor.ToggleOffset, 0);
			method_2(detour.DetourAddress + (ulong)descriptor.ValueOffset, 0);
		}
	}

	private void StartJumpGuard(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor, int virtualKey, float boost)
	{
		_jumpGuardDetour = detour;
		_jumpGuardDescriptor = descriptor;
		_jumpGuardVirtualKey = virtualKey;
		_jumpGuardLastState = false;
		_jumpGuardNextPulseUtcTicks = 0L;
		method_2(detour.DetourAddress + (ulong)descriptor.ValueOffset, BitConverter.ToInt32(BitConverter.GetBytes(boost), 0));
		WriteByte(detour.DetourAddress + (ulong)descriptor.ToggleOffset, 0);
		if (_jumpGuardTimer == null)
		{
			_jumpGuardTimer = new System.Threading.Timer(JumpGuardTick, null, 0, 16);
		}
		else
		{
			_jumpGuardTimer.Change(0, 16);
		}
	}

	private void StopJumpGuard()
	{
		System.Threading.Timer jumpGuardTimer = _jumpGuardTimer;
		_jumpGuardTimer = null;
		jumpGuardTimer?.Dispose();
		RuntimeDetour jumpGuardDetour = _jumpGuardDetour;
		RuntimeProfileHookDescriptor jumpGuardDescriptor = _jumpGuardDescriptor;
		_jumpGuardDetour = null;
		_jumpGuardDescriptor = null;
		_jumpGuardLastState = false;
		_jumpGuardVirtualKey = 0;
		_jumpGuardNextPulseUtcTicks = 0L;
		if (jumpGuardDetour != null && jumpGuardDescriptor != null && jumpGuardDetour.DetourAddress != 0L && !(_handle == IntPtr.Zero))
		{
			try
			{
				WriteByte(jumpGuardDetour.DetourAddress + (ulong)jumpGuardDescriptor.ToggleOffset, 0);
			}
			catch
			{
			}
		}
	}

	private void JumpGuardTick(object state)
	{
		if (Interlocked.Exchange(ref _jumpGuardRunning, 1) == 1)
		{
			return;
		}
		try
		{
			RuntimeDetour jumpGuardDetour = _jumpGuardDetour;
			RuntimeProfileHookDescriptor jumpGuardDescriptor = _jumpGuardDescriptor;
			if (jumpGuardDetour != null && jumpGuardDescriptor != null && jumpGuardDetour.DetourAddress != 0L && IsAlive)
			{
				bool flag = IsKeyDown(_jumpGuardVirtualKey);
				long ticks = DateTime.UtcNow.Ticks;
				if (flag && (!_jumpGuardLastState || ticks >= _jumpGuardNextPulseUtcTicks))
				{
					WriteByte(jumpGuardDetour.DetourAddress + (ulong)jumpGuardDescriptor.ToggleOffset, 1);
					_jumpGuardNextPulseUtcTicks = ticks + 1400000L;
				}
				else
				{
					WriteByte(jumpGuardDetour.DetourAddress + (ulong)jumpGuardDescriptor.ToggleOffset, 0);
				}
				_jumpGuardLastState = flag;
			}
		}
		catch (Exception ex)
		{
			_log("Jump guard stopped: " + ex.Message);
			StopJumpGuard();
		}
		finally
		{
			Interlocked.Exchange(ref _jumpGuardRunning, 0);
		}
	}

	private void StartBoostGuard(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor, int virtualKey, float force)
	{
		_boostGuardDetour = detour;
		_boostGuardDescriptor = descriptor;
		_boostGuardVirtualKey = virtualKey;
		_vehicleBoostEnabled = true;
		_vehicleBoostValue = BitConverter.ToInt32(BitConverter.GetBytes(force), 0);
		ApplyVehicleControlLane(detour, descriptor);
		if (_boostGuardTimer == null)
		{
			_boostGuardTimer = new System.Threading.Timer(BoostGuardTick, null, 0, 16);
		}
		else
		{
			_boostGuardTimer.Change(0, 16);
		}
	}

	private void StopBoostGuard()
	{
		System.Threading.Timer boostGuardTimer = _boostGuardTimer;
		_boostGuardTimer = null;
		boostGuardTimer?.Dispose();
		RuntimeDetour boostGuardDetour = _boostGuardDetour;
		RuntimeProfileHookDescriptor boostGuardDescriptor = _boostGuardDescriptor;
		_boostGuardDetour = null;
		_boostGuardDescriptor = null;
		_boostGuardVirtualKey = 0;
		_vehicleBoostEnabled = false;
		_vehicleBoostValue = 0;
		if (boostGuardDetour != null && boostGuardDescriptor != null && boostGuardDetour.DetourAddress != 0L && !(_handle == IntPtr.Zero))
		{
			try
			{
				ApplyVehicleControlLane(boostGuardDetour, boostGuardDescriptor);
			}
			catch
			{
			}
		}
	}
    private void BoostGuardTick(object state)
    {
        if (Interlocked.Exchange(ref _boostGuardRunning, 1) == 1)
        {
            return;
        }
        try
        {
            RuntimeDetour boostGuardDetour = _boostGuardDetour;
            RuntimeProfileHookDescriptor boostGuardDescriptor = _boostGuardDescriptor;
            if (boostGuardDetour != null && boostGuardDescriptor != null && boostGuardDetour.DetourAddress != 0L && IsAlive)
            {
                ApplyVehicleControlLane(boostGuardDetour, boostGuardDescriptor);
            }
        }
        catch (Exception ex)
        {
            _log("Boost guard stopped: " + ex.Message);
            StopBoostGuard();
        }
        finally
        {
            Interlocked.Exchange(ref _boostGuardRunning, 0);
        }
    }

    private void StartDriftModeGuard(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor, int virtualKey, float amount)
	{
		_driftModeGuardDetour = detour;
		_driftModeGuardDescriptor = descriptor;
		_driftModeGuardVirtualKey = virtualKey;
		_driftModeGuardValue = BitConverter.ToInt32(BitConverter.GetBytes(amount), 0);
		method_2(detour.DetourAddress + (ulong)descriptor.ValueOffset, _driftModeGuardValue);
		WriteByte(detour.DetourAddress + (ulong)descriptor.ToggleOffset, (byte)(IsKeyDown(virtualKey) ? 1 : 0));
		if (_driftModeGuardTimer == null)
		{
			_driftModeGuardTimer = new System.Threading.Timer(DriftModeGuardTick, null, 0, 16);
		}
		else
		{
			_driftModeGuardTimer.Change(0, 16);
		}
	}

	private void StopDriftModeGuard()
	{
		System.Threading.Timer driftModeGuardTimer = _driftModeGuardTimer;
		_driftModeGuardTimer = null;
		driftModeGuardTimer?.Dispose();
		RuntimeDetour driftModeGuardDetour = _driftModeGuardDetour;
		RuntimeProfileHookDescriptor driftModeGuardDescriptor = _driftModeGuardDescriptor;
		_driftModeGuardDetour = null;
		_driftModeGuardDescriptor = null;
		_driftModeGuardVirtualKey = 0;
		_driftModeGuardValue = 0;
		if (driftModeGuardDetour == null || driftModeGuardDescriptor == null || driftModeGuardDetour.DetourAddress == 0L || _handle == IntPtr.Zero)
		{
			return;
		}
		try
		{
			WriteByte(driftModeGuardDetour.DetourAddress + (ulong)driftModeGuardDescriptor.ToggleOffset, 0);
			if (driftModeGuardDescriptor.ValueOffset >= 0)
			{
				method_2(driftModeGuardDetour.DetourAddress + (ulong)driftModeGuardDescriptor.ValueOffset, 0);
			}
		}
		catch
		{
		}
	}

	private void DriftModeGuardTick(object state)
	{
		if (Interlocked.Exchange(ref _driftModeGuardRunning, 1) == 1)
		{
			return;
		}
		try
		{
			RuntimeDetour driftModeGuardDetour = _driftModeGuardDetour;
			RuntimeProfileHookDescriptor driftModeGuardDescriptor = _driftModeGuardDescriptor;
			if (driftModeGuardDetour != null && driftModeGuardDescriptor != null && driftModeGuardDetour.DetourAddress != 0L && IsAlive)
			{
				method_2(driftModeGuardDetour.DetourAddress + (ulong)driftModeGuardDescriptor.ValueOffset, _driftModeGuardValue);
				WriteByte(driftModeGuardDetour.DetourAddress + (ulong)driftModeGuardDescriptor.ToggleOffset, (byte)(IsKeyDown(_driftModeGuardVirtualKey) ? 1 : 0));
			}
		}
		catch (Exception ex)
		{
			_log("Drift Mode guard stopped: " + ex.Message);
			StopDriftModeGuard();
		}
		finally
		{
			Interlocked.Exchange(ref _driftModeGuardRunning, 0);
		}
	}

	private void StartAirControlGuard(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor, int virtualKey, float strength)
	{
		_airControlGuardDetour = detour;
		_airControlGuardDescriptor = descriptor;
		_airControlGuardVirtualKey = virtualKey;
		_airControlStrength = strength;
		_airControlNextPulseUtcTicks = 0L;
		ApplyAirControlInput(detour, descriptor, 0f, 0f);
		if (_airControlGuardTimer == null)
		{
			_airControlGuardTimer = new System.Threading.Timer(AirControlGuardTick, null, 0, 16);
		}
		else
		{
			_airControlGuardTimer.Change(0, 16);
		}
	}

	private void StopAirControlGuard()
	{
		System.Threading.Timer airControlGuardTimer = _airControlGuardTimer;
		_airControlGuardTimer = null;
		airControlGuardTimer?.Dispose();
		RuntimeDetour airControlGuardDetour = _airControlGuardDetour;
		RuntimeProfileHookDescriptor airControlGuardDescriptor = _airControlGuardDescriptor;
		_airControlGuardDetour = null;
		_airControlGuardDescriptor = null;
		_airControlGuardVirtualKey = 0;
		_airControlStrength = 0f;
		_airControlNextPulseUtcTicks = 0L;
		if (airControlGuardDetour != null && airControlGuardDescriptor != null && airControlGuardDetour.DetourAddress != 0L && !(_handle == IntPtr.Zero))
		{
			try
			{
				VehicleControlHookLayout vehicleControlLayout = VehicleControlLayout;
				WriteByte(airControlGuardDetour.DetourAddress + (ulong)vehicleControlLayout.AirControlToggleOffset, 0);
				method_2(airControlGuardDetour.DetourAddress + (ulong)vehicleControlLayout.AirControlValueOffset, 0);
				method_2(airControlGuardDetour.DetourAddress + (ulong)vehicleControlLayout.AirControlSideValueOffset, 0);
				method_2(airControlGuardDetour.DetourAddress + (ulong)vehicleControlLayout.AirControlForwardValueOffset, 0);
			}
			catch
			{
			}
		}
	}

	private void AirControlGuardTick(object state)
	{
		if (Interlocked.Exchange(ref _airControlGuardRunning, 1) == 1)
		{
			return;
		}
		try
		{
			RuntimeDetour airControlGuardDetour = _airControlGuardDetour;
			RuntimeProfileHookDescriptor airControlGuardDescriptor = _airControlGuardDescriptor;
			if (airControlGuardDetour != null && airControlGuardDescriptor != null && airControlGuardDetour.DetourAddress != 0L && IsAlive)
			{
				ReadAirControlInput(out var side, out var forward);
				NormalizeAirControlDirection(ref side, ref forward);
				long ticks = DateTime.UtcNow.Ticks;
				if (_airControlGuardVirtualKey > 0 && IsKeyDown(_airControlGuardVirtualKey) && (Math.Abs(side) > 0.01f || Math.Abs(forward) > 0.01f) && ticks >= _airControlNextPulseUtcTicks)
				{
					ApplyAirControlInput(airControlGuardDetour, airControlGuardDescriptor, side, forward);
					_airControlNextPulseUtcTicks = ticks + 340000L;
				}
				else
				{
					ApplyAirControlInput(airControlGuardDetour, airControlGuardDescriptor, 0f, 0f);
				}
			}
		}
		catch (Exception ex)
		{
			_log("Air Control guard stopped: " + ex.Message);
			StopAirControlGuard();
		}
		finally
		{
			Interlocked.Exchange(ref _airControlGuardRunning, 0);
		}
	}

	private void ApplyAirControlInput(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor, float side, float forward)
	{
		if (detour != null && descriptor != null && detour.DetourAddress != 0L)
		{
			VehicleControlHookLayout vehicleControlLayout = VehicleControlLayout;
			float num = Math.Max(0f, Math.Min(0.95f, _airControlStrength));
			float value = 0f;
			float num2 = ((num <= 0f) ? 0f : Math.Max(12f, Math.Min(72f, num * 90f)));
			float value2 = Math.Max(-72f, Math.Min(72f, side * num2));
			float value3 = Math.Max(-72f, Math.Min(72f, forward * num2));
			method_2(detour.DetourAddress + (ulong)vehicleControlLayout.AirControlValueOffset, BitConverter.ToInt32(BitConverter.GetBytes(value), 0));
			method_2(detour.DetourAddress + (ulong)vehicleControlLayout.AirControlSideValueOffset, BitConverter.ToInt32(BitConverter.GetBytes(value2), 0));
			method_2(detour.DetourAddress + (ulong)vehicleControlLayout.AirControlForwardValueOffset, BitConverter.ToInt32(BitConverter.GetBytes(value3), 0));
			WriteByte(detour.DetourAddress + (ulong)vehicleControlLayout.AirControlToggleOffset, (byte)((Math.Abs(value2) > 0.0001f || Math.Abs(value3) > 0.0001f) ? 1 : 0));
		}
	}

	private void StartNoClipGuard(RuntimeDetour vehicleDetour, int virtualKey)
	{
		StopNoClipGuard();
		_noClipGuardDetour = vehicleDetour;
		_noClipGuardVirtualKey = virtualKey;
		_noClipLastVehiclePointer = 0uL;
		_noClipLastDirX = 0f;
		_noClipLastDirZ = 0f;
		_noClipLastSpeed = 0f;
		_noClipLastPosX = 0f;
		_noClipLastPosZ = 0f;
		_noClipLastDirectionTicks = 0L;
		_noClipDirectionCaptured = false;
		ApplyNoClipToCurrentVehicle();
		if (_noClipGuardTimer == null)
		{
			_noClipGuardTimer = new System.Threading.Timer(NoClipGuardTick, null, 0, 16);
		}
		else
		{
			_noClipGuardTimer.Change(0, 16);
		}
	}

	private void StopNoClipGuard()
	{
		System.Threading.Timer noClipGuardTimer = _noClipGuardTimer;
		_noClipGuardTimer = null;
		noClipGuardTimer?.Dispose();
		_noClipGuardDetour = null;
		_noClipGuardVirtualKey = 0;
		_noClipLastVehiclePointer = 0uL;
		_noClipLastDirX = 0f;
		_noClipLastDirZ = 0f;
		_noClipLastSpeed = 0f;
		_noClipLastPosX = 0f;
		_noClipLastPosZ = 0f;
		_noClipLastDirectionTicks = 0L;
		_noClipDirectionCaptured = false;
	}

	private void NoClipGuardTick(object state)
	{
		if (Interlocked.Exchange(ref _noClipGuardRunning, 1) == 1)
		{
			return;
		}
		try
		{
			if (IsAlive && _noClipGuardDetour != null && _noClipGuardDetour.DetourAddress != 0L)
			{
				ApplyNoClipToCurrentVehicle();
			}
		}
		catch (Exception ex)
		{
			_log("No Clip guard stopped: " + ex.Message);
			StopNoClipGuard();
		}
		finally
		{
			Interlocked.Exchange(ref _noClipGuardRunning, 0);
		}
	}

	private void ApplyNoClipToCurrentVehicle()
	{
		RuntimeDetour noClipGuardDetour = _noClipGuardDetour;
		if (noClipGuardDetour == null || noClipGuardDetour.DetourAddress == 0L)
		{
			return;
		}
		VehicleControlHookLayout vehicleControlLayout = VehicleControlLayout;
		ulong num = method_0(noClipGuardDetour.DetourAddress + (ulong)vehicleControlLayout.VehiclePointerOffset);
		if (num == 0L)
		{
			return;
		}
		if (num != _noClipLastVehiclePointer)
		{
			_noClipLastVehiclePointer = num;
			_noClipDirectionCaptured = false;
		}
		if (!IsWritableMemoryRange(num + 32L, 12) || !IsWritableMemoryRange(num + 80L, 12))
		{
			return;
		}
		byte[] array = ReadBytes(num + 32L, 12);
		byte[] array2 = ReadBytes(num + 80L, 12);
		if (array.Length < 12 || array2.Length < 12)
		{
			return;
		}
		float num2 = BitConverter.ToSingle(array, 0);
		float num3 = BitConverter.ToSingle(array, 8);
		float num4 = BitConverter.ToSingle(array2, 0);
		float num5 = BitConverter.ToSingle(array2, 8);
		if (!IsFiniteFloat(num2) || !IsFiniteFloat(num3) || !IsFiniteFloat(num4) || !IsFiniteFloat(num5))
		{
			return;
		}
		float num6 = (float)Math.Sqrt(num2 * num2 + num3 * num3);
		if (_noClipGuardVirtualKey > 0 && IsKeyDown(_noClipGuardVirtualKey))
		{
			long ticks = DateTime.UtcNow.Ticks;
			bool flag = _noClipDirectionCaptured && ticks - _noClipLastDirectionTicks <= 80000000L;
			float num7 = num4 - _noClipLastPosX;
			float num8 = num5 - _noClipLastPosZ;
			float num9 = (float)Math.Sqrt(num7 * num7 + num8 * num8);
			float num10 = 1f;
			float num11 = 1f;
			if (flag)
			{
				if (num6 > 0.01f)
				{
					num10 = num2 / num6 * _noClipLastDirX + num3 / num6 * _noClipLastDirZ;
				}
				if (num9 > 0.001f)
				{
					num11 = num7 / num9 * _noClipLastDirX + num8 / num9 * _noClipLastDirZ;
				}
			}
			bool flag2 = flag && (num10 < -0.15f || num11 < -0.15f);
			if (num6 > 1.25f && (!flag || num10 > 0.25f || num11 > 0.25f) && !flag2)
			{
				_noClipLastDirX = num2 / num6;
				_noClipLastDirZ = num3 / num6;
				_noClipLastSpeed = Math.Min(num6, 65f);
				_noClipLastDirectionTicks = ticks;
				_noClipDirectionCaptured = true;
				flag = true;
			}
			if (_noClipDirectionCaptured && flag)
			{
				bool flag3 = flag2 || num6 < 8f || num9 < 0.09f || num10 < 0.35f;
				_noClipLastPosX = num4;
				_noClipLastPosZ = num5;
				if (flag3)
				{
					float num12 = Math.Max(0.85f, Math.Min(2.6f, Math.Max(_noClipLastSpeed, 18f) * 0.055f));
					if (flag2)
					{
						num12 = Math.Min(3f, num12 + 0.4f);
					}
					float num13 = num4 + _noClipLastDirX * num12;
					float num14 = num5 + _noClipLastDirZ * num12;
					if (IsFiniteFloat(num13) && IsFiniteFloat(num14))
					{
						WriteFloat(num + 80L, num13);
						WriteFloat(num + 88L, num14);
						WriteFloat(num + 32L, _noClipLastDirX * Math.Max(_noClipLastSpeed, 18f));
						WriteFloat(num + 40L, _noClipLastDirZ * Math.Max(_noClipLastSpeed, 18f));
						_noClipLastPosX = num13;
						_noClipLastPosZ = num14;
					}
				}
			}
			else
			{
				_noClipLastPosX = num4;
				_noClipLastPosZ = num5;
			}
		}
		else
		{
			_noClipDirectionCaptured = false;
			_noClipLastDirX = 0f;
			_noClipLastDirZ = 0f;
			_noClipLastSpeed = 0f;
			_noClipLastDirectionTicks = 0L;
			_noClipLastPosX = num4;
			_noClipLastPosZ = num5;
		}
	}

	private static bool IsFiniteFloat(float value)
	{
		if (!float.IsNaN(value))
		{
			return !float.IsInfinity(value);
		}
		return false;
	}

	private void StartTeleportToWaypointGuard(RuntimeDetour vehicleDetour, RuntimeDetour waypointDetour, RuntimeProfileHookDescriptor waypointDescriptor, List<RuntimeDetour> waypointCopyDetours, List<RuntimeProfileHookDescriptor> waypointCopyDescriptors, int virtualKey)
	{
		_teleportVehicleDetour = vehicleDetour;
		_teleportWaypointDetour = waypointDetour;
		_teleportWaypointDescriptor = waypointDescriptor;
		_teleportWaypointCopyDetours = waypointCopyDetours ?? new List<RuntimeDetour>();
		_teleportWaypointCopyDescriptors = waypointCopyDescriptors ?? new List<RuntimeProfileHookDescriptor>();
		_teleportVirtualKey = virtualKey;
		_teleportKeyLastState = false;
		_teleportCooldownUntilUtcTicks = 0L;
		_teleportRepeatPosition = null;
		_teleportRepeatUntilUtcTicks = 0L;
		_teleportLastSource = string.Empty;
		_teleportSavedPosition = null;
		_teleportSavedName = string.Empty;
		ClearTeleportWaypointCaptures(_teleportWaypointCopyDetours, _teleportWaypointCopyDescriptors, _teleportWaypointDetour, _teleportWaypointDescriptor);
		if (_teleportToWaypointGuardTimer == null)
		{
			_teleportToWaypointGuardTimer = new System.Threading.Timer(TeleportToWaypointGuardTick, null, 0, 16);
		}
		else
		{
			_teleportToWaypointGuardTimer.Change(0, 16);
		}
	}

	private void StartSavedLocationTeleportGuard(RuntimeDetour vehicleDetour, int virtualKey, byte[] position, string name)
	{
		_teleportVehicleDetour = vehicleDetour;
		_teleportWaypointDetour = null;
		_teleportWaypointDescriptor = null;
		_teleportWaypointCopyDetours = new List<RuntimeDetour>();
		_teleportWaypointCopyDescriptors = new List<RuntimeProfileHookDescriptor>();
		_teleportVirtualKey = virtualKey;
		_teleportKeyLastState = false;
		_teleportCooldownUntilUtcTicks = 0L;
		_teleportRepeatPosition = null;
		_teleportRepeatUntilUtcTicks = 0L;
		_teleportLastSource = string.Empty;
		_teleportSavedPosition = CopyTeleportPosition(position);
		_teleportSavedName = (string.IsNullOrWhiteSpace(name) ? "saved spot" : name.Trim());
		if (_teleportToWaypointGuardTimer == null)
		{
			_teleportToWaypointGuardTimer = new System.Threading.Timer(TeleportToWaypointGuardTick, null, 0, 16);
		}
		else
		{
			_teleportToWaypointGuardTimer.Change(0, 16);
		}
	}

	private void ClearTeleportWaypointCaptures(List<RuntimeDetour> waypointCopyDetours, List<RuntimeProfileHookDescriptor> waypointCopyDescriptors, RuntimeDetour waypointDetour, RuntimeProfileHookDescriptor waypointDescriptor)
	{
		try
		{
			int num = Math.Min(waypointCopyDetours?.Count ?? 0, waypointCopyDescriptors?.Count ?? 0);
			for (int i = 0; i < num; i++)
			{
				ClearTeleportCapture(waypointCopyDetours[i], waypointCopyDescriptors[i]);
			}
			ClearTeleportCapture(waypointDetour, waypointDescriptor);
		}
		catch
		{
		}
	}

	private void ClearTeleportCapture(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor)
	{
		if (detour != null && descriptor != null && detour.DetourAddress != 0L)
		{
			if (descriptor.CaptureOffset >= 0)
			{
				WriteBytes(detour.DetourAddress + (ulong)descriptor.CaptureOffset, new byte[16]);
			}
			if (descriptor.ObjectPointerOffset >= 0)
			{
				method_3(detour.DetourAddress + (ulong)descriptor.ObjectPointerOffset, 0uL);
			}
		}
	}

	private void StopTeleportToWaypointGuard()
	{
		System.Threading.Timer teleportToWaypointGuardTimer = _teleportToWaypointGuardTimer;
		_teleportToWaypointGuardTimer = null;
		teleportToWaypointGuardTimer?.Dispose();
		RuntimeDetour teleportVehicleDetour = _teleportVehicleDetour;
		if (teleportVehicleDetour != null && teleportVehicleDetour.DetourAddress != 0L && _handle != IntPtr.Zero)
		{
			try
			{
				VehicleControlHookLayout vehicleControlLayout = VehicleControlLayout;
				WriteByte(teleportVehicleDetour.DetourAddress + (ulong)vehicleControlLayout.TeleportToggleOffset, 0);
			}
			catch
			{
			}
		}
		_teleportVehicleDetour = null;
		_teleportWaypointDetour = null;
		_teleportWaypointDescriptor = null;
		_teleportWaypointCopyDetours = new List<RuntimeDetour>();
		_teleportWaypointCopyDescriptors = new List<RuntimeProfileHookDescriptor>();
		_teleportVirtualKey = 0;
		_teleportKeyLastState = false;
		_teleportCooldownUntilUtcTicks = 0L;
		_teleportRepeatPosition = null;
		_teleportRepeatUntilUtcTicks = 0L;
		_teleportLastSource = string.Empty;
		_teleportSavedPosition = null;
		_teleportSavedName = string.Empty;
	}

	private void TeleportToWaypointGuardTick(object state)
	{
		if (Interlocked.Exchange(ref _teleportToWaypointGuardRunning, 1) == 1)
		{
			return;
		}
		try
		{
			if (!IsAlive)
			{
				return;
			}
			bool flag = _teleportVirtualKey > 0 && IsKeyDown(_teleportVirtualKey);
			long ticks = DateTime.UtcNow.Ticks;
			if (flag && !_teleportKeyLastState && ticks >= _teleportCooldownUntilUtcTicks)
			{
				if (_teleportSavedPosition != null)
				{
					TeleportVehicleToSavedLocation(_teleportVehicleDetour, _teleportSavedPosition, _teleportSavedName);
				}
				else
				{
					TeleportVehicleToWaypoint();
				}
				_teleportCooldownUntilUtcTicks = ticks + 6500000L;
			}
			ApplyPendingTeleport(ticks);
			_teleportKeyLastState = flag;
		}
		catch (Exception ex)
		{
			_log("Teleport To Waypoint guard stopped: " + ex.Message);
			StopTeleportToWaypointGuard();
		}
		finally
		{
			Interlocked.Exchange(ref _teleportToWaypointGuardRunning, 0);
		}
	}

	private void TeleportVehicleToWaypoint()
	{
		RuntimeDetour teleportVehicleDetour = _teleportVehicleDetour;
		if (teleportVehicleDetour == null)
		{
			throw new InvalidOperationException("Teleport hook is not ready yet.");
		}
		VehicleControlHookLayout vehicleControlLayout = VehicleControlLayout;
		ulong num = method_0(teleportVehicleDetour.DetourAddress + (ulong)vehicleControlLayout.VehiclePointerOffset);
		if (!TryReadBestWaypointPosition(num, out var position))
		{
			_log("Teleport To Waypoint waiting for a waypoint. Set a waypoint, open/close the map once if needed, then press the key again.");
			return;
		}
		if (num != 0L)
		{
			position = BuildTeleportVehiclePosition(num, position);
		}
		QueueVehicleControlTeleport(teleportVehicleDetour, position);
		if (num != 0L)
		{
			ApplyTeleportPosition(num, position);
			_teleportRepeatPosition = position;
			_teleportRepeatUntilUtcTicks = DateTime.UtcNow.Ticks + 6500000L;
		}
		string text = (string.IsNullOrEmpty(_teleportLastSource) ? "unknown" : _teleportLastSource);
		_log("Teleport To Waypoint fired from " + text + " to " + FormatTeleportPosition(position) + ".");
	}

	private void TeleportVehicleToSavedLocation(RuntimeDetour vehicleDetour, byte[] savedPosition, string name)
	{
		if (vehicleDetour == null)
		{
			throw new InvalidOperationException("Teleport hook is not ready yet.");
		}
		if (!IsValidTeleportPosition(savedPosition))
		{
			throw new InvalidOperationException("Saved teleport location is not valid.");
		}
		ulong num = ReadCurrentVehiclePointer(vehicleDetour);
		byte[] array = ((num == 0L) ? CopyTeleportPosition(savedPosition) : BuildTeleportVehiclePosition(num, savedPosition));
		QueueVehicleControlTeleport(vehicleDetour, array);
		if (num != 0L)
		{
			ApplyTeleportPosition(num, array);
			_teleportRepeatPosition = array;
			_teleportRepeatUntilUtcTicks = DateTime.UtcNow.Ticks + 6500000L;
		}
		_log("Saved Location Teleport fired to " + (string.IsNullOrWhiteSpace(name) ? "saved spot" : name) + " at " + FormatTeleportPosition(array) + ".");
	}

	private ulong ReadCurrentVehiclePointer(RuntimeDetour vehicleDetour)
	{
		if (vehicleDetour != null && vehicleDetour.DetourAddress != 0L)
		{
			VehicleControlHookLayout vehicleControlLayout = VehicleControlLayout;
			return method_0(vehicleDetour.DetourAddress + (ulong)vehicleControlLayout.VehiclePointerOffset);
		}
		return 0uL;
	}

	private static byte[] CopyTeleportPosition(byte[] position)
	{
		byte[] array = new byte[16];
		if (position != null)
		{
			Buffer.BlockCopy(position, 0, array, 0, Math.Min(16, position.Length));
		}
		return array;
	}

	private void QueueVehicleControlTeleport(RuntimeDetour vehicleDetour, byte[] position)
	{
		if (vehicleDetour != null && vehicleDetour.DetourAddress != 0L && position != null && position.Length >= 16)
		{
			VehicleControlHookLayout vehicleControlLayout = VehicleControlLayout;
			WriteBytes(vehicleDetour.DetourAddress + (ulong)vehicleControlLayout.TeleportPositionOffset, position);
			WriteByte(vehicleDetour.DetourAddress + (ulong)vehicleControlLayout.TeleportToggleOffset, 1);
		}
	}

	private byte[] BuildTeleportVehiclePosition(ulong vehiclePointer, byte[] position)
	{
		byte[] array = new byte[16];
		byte[] array2 = ((vehiclePointer == 0L) ? null : ReadBytes(vehiclePointer + 80L, 16));
		if (array2 != null && array2.Length >= 16)
		{
			Buffer.BlockCopy(array2, 0, array, 0, 16);
		}
		else if (position != null && position.Length >= 16)
		{
			Buffer.BlockCopy(position, 0, array, 0, 16);
		}
		if (position != null && position.Length >= 12)
		{
			Buffer.BlockCopy(position, 0, array, 0, 12);
		}
		return array;
	}

	private void ApplyPendingTeleport(long nowTicks)
	{
		byte[] teleportRepeatPosition = _teleportRepeatPosition;
		if (teleportRepeatPosition == null)
		{
			return;
		}
		if (nowTicks > _teleportRepeatUntilUtcTicks)
		{
			_teleportRepeatPosition = null;
			_teleportRepeatUntilUtcTicks = 0L;
			return;
		}
		RuntimeDetour teleportVehicleDetour = _teleportVehicleDetour;
		if (teleportVehicleDetour != null && teleportVehicleDetour.DetourAddress != 0L)
		{
			VehicleControlHookLayout vehicleControlLayout = VehicleControlLayout;
			ulong num = method_0(teleportVehicleDetour.DetourAddress + (ulong)vehicleControlLayout.VehiclePointerOffset);
			if (num != 0L)
			{
				ApplyTeleportPosition(num, teleportRepeatPosition);
			}
		}
	}

	private void ApplyTeleportPosition(ulong vehiclePointer, byte[] position)
	{
		if (position != null && position.Length >= 16)
		{
			WriteBytes(vehiclePointer + 80L, position);
			WriteBytes(vehiclePointer + 32L, new byte[16]);
		}
	}

	private bool TryReadBestWaypointPosition(ulong vehiclePointer, out byte[] position)
	{
		position = null;
		_teleportLastSource = string.Empty;
		byte[] current = ((vehiclePointer == 0L) ? null : ReadBytes(vehiclePointer + 80L, 16));
		double bestScore = double.MinValue;
		ConsiderTeleportCaptureSources(current, ref position, ref bestScore, routeVectorFallbackOnly: false);
		RuntimeDetour teleportWaypointDetour = _teleportWaypointDetour;
		RuntimeProfileHookDescriptor teleportWaypointDescriptor = _teleportWaypointDescriptor;
		if (teleportWaypointDetour != null && teleportWaypointDescriptor != null && teleportWaypointDetour.DetourAddress != 0L && teleportWaypointDescriptor.ObjectPointerOffset >= 0)
		{
			ulong num = method_0(teleportWaypointDetour.DetourAddress + (ulong)teleportWaypointDescriptor.ObjectPointerOffset);
			if (num != 0L)
			{
				ConsiderTeleportDestinationObject(num, current, ref position, ref bestScore, GetTeleportObjectBasePriority(teleportWaypointDescriptor), teleportWaypointDescriptor.Key);
			}
		}
		if (position == null)
		{
			ConsiderTeleportCaptureSources(current, ref position, ref bestScore, routeVectorFallbackOnly: true);
		}
		return position != null;
	}

	private void ConsiderTeleportCaptureSources(byte[] current, ref byte[] position, ref double bestScore, bool routeVectorFallbackOnly)
	{
		List<RuntimeDetour> teleportWaypointCopyDetours = _teleportWaypointCopyDetours;
		List<RuntimeProfileHookDescriptor> teleportWaypointCopyDescriptors = _teleportWaypointCopyDescriptors;
		int num = Math.Min(teleportWaypointCopyDetours?.Count ?? 0, teleportWaypointCopyDescriptors?.Count ?? 0);
		for (int i = 0; i < num; i++)
		{
			RuntimeDetour runtimeDetour = teleportWaypointCopyDetours[i];
			RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = teleportWaypointCopyDescriptors[i];
			if (runtimeDetour == null || runtimeProfileHookDescriptor == null || runtimeDetour.DetourAddress == 0L)
			{
				continue;
			}
			bool flag = IsRawRouteVectorTeleportSource(runtimeProfileHookDescriptor);
			if (routeVectorFallbackOnly == flag)
			{
				if (runtimeProfileHookDescriptor.CaptureOffset >= 0)
				{
					byte[] candidate = ReadBytes(runtimeDetour.DetourAddress + (ulong)runtimeProfileHookDescriptor.CaptureOffset, 16);
					ConsiderTeleportPosition(candidate, current, ref position, ref bestScore, GetTeleportCapturePriority(runtimeProfileHookDescriptor), runtimeProfileHookDescriptor.Key + ".capture");
				}
				if (runtimeProfileHookDescriptor.ObjectPointerOffset >= 0)
				{
					ulong objectPointer = method_0(runtimeDetour.DetourAddress + (ulong)runtimeProfileHookDescriptor.ObjectPointerOffset);
					ConsiderTeleportDestinationObject(objectPointer, current, ref position, ref bestScore, GetTeleportObjectBasePriority(runtimeProfileHookDescriptor), runtimeProfileHookDescriptor.Key);
				}
			}
		}
	}

	private static bool IsRawRouteVectorTeleportSource(RuntimeProfileHookDescriptor descriptor)
	{
		if (descriptor != null && !string.IsNullOrEmpty(descriptor.Key))
		{
			return descriptor.Key.IndexOf("RouteVector", StringComparison.OrdinalIgnoreCase) >= 0;
		}
		return false;
	}

	private void ConsiderTeleportDestinationObject(ulong objectPointer, byte[] current, ref byte[] best, ref double bestScore)
	{
		ConsiderTeleportDestinationObject(objectPointer, current, ref best, ref bestScore, 0.0, "object");
	}

	private void ConsiderTeleportDestinationObject(ulong objectPointer, byte[] current, ref byte[] best, ref double bestScore, double basePriority, string source)
	{
		if (!LooksLikeProcessPointer(objectPointer) || !IsReadableMemoryRange(objectPointer, 256))
		{
			return;
		}
		if (!string.IsNullOrEmpty(source) && source.IndexOf("SatNavRouteObject", StringComparison.OrdinalIgnoreCase) >= 0)
		{
			ConsiderTeleportSatNavRouteObject(objectPointer, current, ref best, ref bestScore, basePriority, source);
		}
		ulong[] array = new ulong[7] { 1888uL, 144uL, 160uL, 128uL, 1088uL, 560uL, 68uL };
		for (int i = 0; i < array.Length; i++)
		{
			ulong address = objectPointer + array[i];
			if (IsReadableMemoryRange(address, 16))
			{
				byte[] candidate = ReadBytes(address, 16);
				ConsiderTeleportPosition(candidate, current, ref best, ref bestScore, basePriority + GetTeleportObjectOffsetPriority(array[i]), source + "+0x" + array[i].ToString("X", CultureInfo.InvariantCulture));
			}
		}
	}

	private void ConsiderTeleportSatNavRouteObject(ulong objectPointer, byte[] current, ref byte[] best, ref double bestScore, double basePriority, string source)
	{
		int num = method_1(objectPointer + 144L);
		if (num > 0 && num <= 4096)
		{
			ConsiderTeleportVectorRange(objectPointer, 160uL, 168uL, current, ref best, ref bestScore, basePriority + 500000000000000.0, source + ".routeA");
			ConsiderTeleportVectorRange(objectPointer, 184uL, 192uL, current, ref best, ref bestScore, basePriority + 400000000000000.0, source + ".routeB");
			ConsiderTeleportVectorRange(objectPointer, 232uL, 240uL, current, ref best, ref bestScore, basePriority + 300000000000000.0, source + ".routeC");
			ConsiderTeleportVectorRange(objectPointer, 416uL, 424uL, current, ref best, ref bestScore, basePriority + 200000000000000.0, source + ".routeD");
		}
	}

	private void ConsiderTeleportVectorRange(ulong objectPointer, ulong beginOffset, ulong endOffset, byte[] current, ref byte[] best, ref double bestScore, double priority, string source)
	{
		if (!IsReadableMemoryRange(objectPointer + beginOffset, 16))
		{
			return;
		}
		ulong num = method_0(objectPointer + beginOffset);
		ulong num2 = method_0(objectPointer + endOffset);
		if (!LooksLikeProcessPointer(num) || !LooksLikeProcessPointer(num2) || num2 <= num)
		{
			return;
		}
		ulong num3 = num2 - num;
		if (num3 < 16L || num3 > 131072L)
		{
			return;
		}
		ulong address = num2 - 16L;
		if (IsReadableMemoryRange(address, 16))
		{
			ConsiderTeleportPosition(ReadBytes(address, 16), current, ref best, ref bestScore, priority, source + ".last");
		}
		ulong num4 = ((num3 % 16L == 0L) ? 16uL : 4uL);
		ulong num5 = ((num3 > 1024L) ? (num2 - 1024L) : num);
		for (ulong num6 = num5; num6 + 16L <= num2; num6 += num4)
		{
			if (IsReadableMemoryRange(num6, 16))
			{
				ConsiderTeleportPosition(ReadBytes(num6, 16), current, ref best, ref bestScore, priority - (double)(num2 - num6), source + "+0x" + (num6 - num).ToString("X", CultureInfo.InvariantCulture));
			}
		}
	}

	private static double GetTeleportCapturePriority(RuntimeProfileHookDescriptor descriptor)
	{
		if (descriptor != null && !string.IsNullOrEmpty(descriptor.Key))
		{
			if (descriptor.Key.IndexOf("DestinationSetter", StringComparison.OrdinalIgnoreCase) >= 0)
			{
				return 100000000000000.0;
			}
			if (descriptor.Key.IndexOf("SatNav", StringComparison.OrdinalIgnoreCase) >= 0)
			{
				return 80000000000000.0;
			}
			if (descriptor.Key.IndexOf("RouteVectorB", StringComparison.OrdinalIgnoreCase) >= 0)
			{
				return 1000000000000.0;
			}
			if (descriptor.Key.IndexOf("RouteVector", StringComparison.OrdinalIgnoreCase) >= 0)
			{
				return 500000000000.0;
			}
			return 0.0;
		}
		return 0.0;
	}

	private static double GetTeleportObjectBasePriority(RuntimeProfileHookDescriptor descriptor)
	{
		if (descriptor != null && !string.IsNullOrEmpty(descriptor.Key))
		{
			if (descriptor.Key.IndexOf("NavigationDestinationPointer", StringComparison.OrdinalIgnoreCase) < 0 && descriptor.Key.IndexOf("CurrentDestinationPointer", StringComparison.OrdinalIgnoreCase) < 0 && descriptor.Key.IndexOf("DestinationSetter", StringComparison.OrdinalIgnoreCase) < 0)
			{
				if (descriptor.Key.IndexOf("SatNavRouteObject", StringComparison.OrdinalIgnoreCase) >= 0)
				{
					return 150000000000000.0;
				}
				if (descriptor.Key.IndexOf("SatNav", StringComparison.OrdinalIgnoreCase) >= 0)
				{
					return 100000000000000.0;
				}
				if (descriptor.Key.IndexOf("RouteVector", StringComparison.OrdinalIgnoreCase) >= 0)
				{
					return 1000000000000.0;
				}
				return 0.0;
			}
			return 200000000000000.0;
		}
		return 0.0;
	}

	private static double GetTeleportObjectOffsetPriority(ulong offset)
	{
		return offset switch
		{
			144uL => 3000000000000.0, 
			1888uL => 2000000000000.0, 
			160uL => 1000000000000.0, 
			128uL => 500000000000.0, 
			_ => 0.0, 
		};
	}

	private void ConsiderTeleportPosition(byte[] candidate, byte[] current, ref byte[] best, ref double bestScore, double priority, string source)
	{
		if (candidate == null || candidate.Length < 12 || !IsValidTeleportPosition(candidate))
		{
			return;
		}
		double num = 1.0;
		if (current != null && current.Length >= 12 && IsValidTeleportPosition(current))
		{
			float num2 = BitConverter.ToSingle(candidate, 0) - BitConverter.ToSingle(current, 0);
			float num3 = BitConverter.ToSingle(candidate, 4) - BitConverter.ToSingle(current, 4);
			float num4 = BitConverter.ToSingle(candidate, 8) - BitConverter.ToSingle(current, 8);
			num = (double)num2 * (double)num2 + (double)num3 * (double)num3 + (double)num4 * (double)num4;
			if (num < 9.0)
			{
				return;
			}
		}
		num += priority;
		if (!(num <= bestScore))
		{
			bestScore = num;
			best = candidate;
			_teleportLastSource = source ?? string.Empty;
		}
	}

	private static bool IsValidTeleportPosition(byte[] position)
	{
		if (position != null && position.Length >= 12)
		{
			float value = BitConverter.ToSingle(position, 0);
			float value2 = BitConverter.ToSingle(position, 4);
			float value3 = BitConverter.ToSingle(position, 8);
			if (IsValidTeleportCoordinate(value) && IsValidTeleportCoordinate(value2) && IsValidTeleportCoordinate(value3) && !LooksLikePointerBackedVector(position) && (!(Math.Abs(value) < 0.001f) || !(Math.Abs(value2) < 0.001f) || Math.Abs(value3) >= 0.001f))
			{
				float num = Math.Max(Math.Abs(value), Math.Max(Math.Abs(value2), Math.Abs(value3)));
				if (num > 250000f)
				{
					int num2 = 0;
					if (Math.Abs(value) > 1000f)
					{
						num2++;
					}
					if (Math.Abs(value2) > 1000f)
					{
						num2++;
					}
					if (Math.Abs(value3) > 1000f)
					{
						num2++;
					}
					if (num2 < 2)
					{
						return false;
					}
				}
				return true;
			}
			return false;
		}
		return false;
	}

	private static string FormatTeleportPosition(byte[] position)
	{
		if (position != null && position.Length >= 12)
		{
			return "X " + BitConverter.ToSingle(position, 0).ToString("0.0", CultureInfo.InvariantCulture) + ", Y " + BitConverter.ToSingle(position, 4).ToString("0.0", CultureInfo.InvariantCulture) + ", Z " + BitConverter.ToSingle(position, 8).ToString("0.0", CultureInfo.InvariantCulture);
		}
		return "unknown";
	}

	private static bool IsValidTeleportCoordinate(float value)
	{
		if (!float.IsNaN(value) && !float.IsInfinity(value))
		{
			return Math.Abs(value) < 10000000f;
		}
		return false;
	}

	private static bool LooksLikePointerBackedVector(byte[] position)
	{
		if (position != null && position.Length >= 16)
		{
			if (!LooksLikeProcessPointer(BitConverter.ToUInt64(position, 0)))
			{
				return LooksLikeProcessPointer(BitConverter.ToUInt64(position, 8));
			}
			return true;
		}
		return false;
	}

	private static bool IsLikelyTeleportPointer(ulong pointer)
	{
		return LooksLikeProcessPointer(pointer);
	}

	private static bool LooksLikeProcessPointer(ulong value)
	{
		if (value >= 4294967296L && value <= 140737488355327L)
		{
			return value >> 32 < 65536L;
		}
		return false;
	}

	private static void NormalizeAirControlDirection(ref float side, ref float forward)
	{
		float num = Math.Abs(side);
		float num2 = Math.Abs(forward);
		if (num <= 0.01f && num2 <= 0.01f)
		{
			side = 0f;
			forward = 0f;
		}
		else if (num2 >= num)
		{
			forward = ((forward < 0f) ? (-1f) : 1f);
			side = 0f;
		}
		else
		{
			side = ((side < 0f) ? (-1f) : 1f);
			forward = 0f;
		}
	}

	private static void ReadAirControlInput(out float side, out float forward)
	{
		side = 0f;
		forward = 0f;
		if (IsKeyDown(65) || IsKeyDown(37))
		{
			side -= 1f;
		}
		if (IsKeyDown(68) || IsKeyDown(39))
		{
			side += 1f;
		}
		if (IsKeyDown(87) || IsKeyDown(38))
		{
			forward += 1f;
		}
		if (IsKeyDown(83) || IsKeyDown(40) || IsKeyDown(66))
		{
			forward -= 1f;
		}
		for (int i = 0; i < 4; i++)
		{
			if (Native.TryXInputGetState(i, out var state))
			{
				side += NormalizeThumbAxis(state.Gamepad.sThumbLX, 7849);
				forward += NormalizeThumbAxis(state.Gamepad.sThumbLY, 7849);
				if ((state.Gamepad.wButtons & 4) != 0)
				{
					side -= 1f;
				}
				if ((state.Gamepad.wButtons & 8) != 0)
				{
					side += 1f;
				}
				if ((state.Gamepad.wButtons & 1) != 0)
				{
					forward += 1f;
				}
				if ((state.Gamepad.wButtons & 2) != 0)
				{
					forward -= 1f;
				}
			}
		}
		side = Math.Max(-1f, Math.Min(1f, side));
		forward = Math.Max(-1f, Math.Min(1f, forward));
	}

	private static float NormalizeThumbAxis(short raw, int deadzone)
	{
		int num = Math.Abs((int)raw);
		if (num <= deadzone)
		{
			return 0f;
		}
		float val = (float)(num - deadzone) / (32767f - (float)deadzone);
		val = Math.Max(0f, Math.Min(1f, val));
		if (raw >= 0)
		{
			return val;
		}
		return 0f - val;
	}

	private bool IsBrakeInputPressed()
	{
		if (!IsKeyDown(_brakeVirtualKey))
		{
			return IsGamepadBrakePressed();
		}
		return true;
	}

	private static bool IsKeyDown(int virtualKey)
	{
		return (Native.GetAsyncKeyState(virtualKey) & -32768) != 0;
	}

	private static bool IsGamepadBrakePressed()
	{
		try
		{
			for (int i = 0; i < 4; i++)
			{
				if (Native.TryXInputGetState(i, out var state) && (state.Gamepad.bLeftTrigger > 18 || (state.Gamepad.wButtons & 0x100) != 0))
				{
					return true;
				}
			}
		}
		catch
		{
		}
		return false;
	}

	public void SetBestWheelspinOddsRuntime(bool enabled)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		lock (_bestWheelspinPatchLock)
		{
			if (!enabled)
			{
				int num = RestoreBestWheelspinOddsPatches();
				_log("Best Spins runtime hook disabled. Restored " + num.ToString(CultureInfo.InvariantCulture) + " Tombola patch(es).");
				return;
			}
			EnsureCrcBypass();
			RestoreBestWheelspinOddsPatches();
			byte[] array = ReadBytes(_mainBase, _mainSize);
			if (array.Length == 0)
			{
				throw new InvalidOperationException("Could not read main module memory for Best Spins hook scan.");
			}
			int num2 = PatchBestWheelspinSpinValueMetadataHooks(array);
			if (num2 <= 0)
			{
				throw new InvalidOperationException("Best Spins runtime hook was not armed because the Tombola SpinValue rarity metadata was not found.");
			}
			_log("Best Spins runtime hook enabled. Tombola SpinValue rarity conversions are forced to FH6's rarest tier value (3) while Luna stays attached.");
		}
	}

	private int PatchBestWheelspinSpinValueMetadataHooks(byte[] module)
	{
		ulong enumReadByValue = _mainBase + 48792960L;
		Dictionary<ulong, ulong> detours = new Dictionary<ulong, ulong>();
		int num = 0;
		num = 0 + PatchBestWheelspinSpinValueBlock(module, "SpinValue", 144, enumReadByValue, detours);
		return num + PatchBestWheelspinSpinValueBlock(module, "TombolaRemainingSpinItem", 128, enumReadByValue, detours);
	}

	private int PatchBestWheelspinSpinValueBlock(byte[] module, string label, int scanBytes, ulong enumReadByValue, Dictionary<ulong, ulong> detours)
	{
		byte[] bytes = Encoding.ASCII.GetBytes(label + "\0");
		int num = 0;
		foreach (int item in Pattern.FindBytes(module, bytes, 8))
		{
			for (int i = 8; i <= scanBytes; i += 8)
			{
				ulong address = (ulong)((long)_mainBase + (long)item + i);
				ulong num2 = method_0(address);
				if (num2 != enumReadByValue)
				{
					continue;
				}
				byte[] array = ReadBytes(address, 8);
				if (array.Length == 8)
				{
					if (!detours.TryGetValue(num2, out var value))
					{
						value = CreateBestWheelspinSpinValueDetour(num2);
						detours.Add(num2, value);
					}
					WriteProtectedBytes(address, BitConverter.GetBytes(value));
					_bestWheelspinOddsPatches.Add(new MemoryPatch
					{
						Address = address,
						Original = array
					});
					num++;
					_log("Best Spins patched " + label + " SpinValue converter pointer at 0x" + address.ToString("X") + " from 0x" + num2.ToString("X") + " to detour 0x" + value.ToString("X") + ".");
				}
			}
		}
		return num;
	}

	private ulong CreateBestWheelspinSpinValueDetour(ulong originalTarget)
	{
		List<byte> list = new List<byte>();
		list.AddRange(new byte[5] { 72, 137, 92, 36, 8 });
		list.AddRange(new byte[5] { 72, 137, 108, 36, 16 });
		list.AddRange(new byte[1] { 86 });
		list.AddRange(new byte[1] { 87 });
		list.AddRange(new byte[2] { 65, 86 });
		list.AddRange(new byte[4] { 72, 131, 236, 48 });
		list.AddRange(new byte[3] { 72, 139, 250 });
		list.AddRange(new byte[3] { 72, 139, 241 });
		list.AddRange(new byte[3] { 77, 133, 201 });
		list.AddRange(new byte[2] { 117, 15 });
		list.AddRange(new byte[3] { 76, 137, 10 });
		list.AddRange(new byte[2] { 72, 184 });
		list.AddRange(BitConverter.GetBytes(originalTarget + 98L));
		list.AddRange(new byte[2] { 255, 224 });
		list.AddRange(new byte[5] { 189, 3, 0, 0, 0 });
		list.AddRange(new byte[2] { 72, 184 });
		list.AddRange(BitConverter.GetBytes(originalTarget + 38L));
		list.AddRange(new byte[2] { 255, 224 });
		IntPtr intPtr = Native.VirtualAllocEx(_handle, IntPtr.Zero, (UIntPtr)(ulong)Math.Max(4096, list.Count), 12288u, 64u);
		if (intPtr == IntPtr.Zero)
		{
			throw new InvalidOperationException("VirtualAllocEx failed while creating Best Spins detour.");
		}
		ulong num = (ulong)intPtr.ToInt64();
		WriteBytes(num, list.ToArray());
		_bestWheelspinOddsDetours.Add(num);
		return num;
	}

	private int RestoreBestWheelspinOddsPatches()
	{
		lock (_bestWheelspinPatchLock)
		{
			int num = 0;
			for (int num2 = _bestWheelspinOddsPatches.Count - 1; num2 >= 0; num2--)
			{
				try
				{
					WriteProtectedBytes(_bestWheelspinOddsPatches[num2].Address, _bestWheelspinOddsPatches[num2].Original);
					num++;
				}
				catch (Exception ex)
				{
					_log("Could not restore Best Spins patch at 0x" + _bestWheelspinOddsPatches[num2].Address.ToString("X") + ": " + ex.Message);
				}
			}
			_bestWheelspinOddsPatches.Clear();
			for (int num3 = _bestWheelspinOddsDetours.Count - 1; num3 >= 0; num3--)
			{
				try
				{
					Native.VirtualFreeEx(_handle, new IntPtr((long)_bestWheelspinOddsDetours[num3]), UIntPtr.Zero, 32768u);
				}
				catch
				{
				}
			}
			_bestWheelspinOddsDetours.Clear();
			return num;
		}
	}

	private void ApplyTimeAttackInfluenceMultiplier(float multiplier, bool enabled)
	{
		if (!enabled)
		{
			int num = RestoreTimeAttackInfluencePatches();
			_log("Time Attack XP Multiplier disabled. Restored " + num.ToString(CultureInfo.InvariantCulture) + " patched bonus float(s).");
			return;
		}
		if (!float.IsNaN(multiplier) && !float.IsInfinity(multiplier) && multiplier >= 1f)
		{
			if (multiplier > 1000000f)
			{
				throw new InvalidOperationException("Time Attack XP Multiplier must be 1000000 or lower for this guarded patch path.");
			}
			lock (_timeAttackPatchLock)
			{
				RestoreTimeAttackInfluencePatches();
				Stopwatch scanWatch = Stopwatch.StartNew();
				bool timedOut;
				List<TimeAttackFloatCandidate> list = FindTimeAttackInfluenceRecordFloatCandidates(scanWatch, out timedOut);
				int num2 = 0;
				foreach (TimeAttackFloatCandidate item in list)
				{
					if (!IsLiveTimeAttackCandidate(item))
					{
						continue;
					}
					byte[] array = ReadBytes(item.Address, 4);
					if (array.Length < 4)
					{
						continue;
					}
					float value = BitConverter.ToSingle(array, 0);
					if (IsTimeAttackRuntimeBonusValue(value))
					{
						try
						{
							float timeAttackPatchValue = GetTimeAttackPatchValue(multiplier, item.PatchMode);
							WriteTimeAttackBytes(item.Address, BitConverter.GetBytes(timeAttackPatchValue));
							_timeAttackInfluencePatches.Add(new MemoryPatch
							{
								Address = item.Address,
								Original = array
							});
							num2++;
							Action<string> log = _log;
							string[] array2 = new string[11]
							{
								"Time Attack XP candidate patched at 0x", null, null, null, null, null, null, null, null, null,
								null
							};
							ulong address = item.Address;
							array2[1] = address.ToString("X");
							array2[2] = " from x";
							array2[3] = FormatFloatInvariant(value);
							array2[4] = " to raw x";
							array2[5] = FormatFloatInvariant(timeAttackPatchValue);
							array2[6] = " for requested x";
							array2[7] = FormatFloatInvariant(multiplier);
							array2[8] = " near 0x";
							ulong anchor = item.Anchor;
							array2[9] = anchor.ToString("X");
							array2[10] = ".";
							log(string.Concat(array2));
						}
						catch (Exception ex)
						{
							Action<string> log2 = _log;
							ulong address2 = item.Address;
							log2("Skipped volatile Time Attack XP candidate at 0x" + address2.ToString("X") + ": " + ex.Message);
						}
					}
				}
				if (num2 == 0)
				{
					string text = (timedOut ? ("stopped at the " + 10000.ToString(CultureInfo.InvariantCulture) + "ms safety limit") : "finished");
					_log("Time Attack XP Multiplier ID-record scan " + text + ". No TimeAttackInfluence runtime record bonus slots were patched.");
					throw new InvalidOperationException("Time Attack XP Multiplier was not armed because the TimeAttackInfluence runtime record was not found in the current live scan.");
				}
				_log("Time Attack XP Multiplier enabled. Patched " + num2.ToString(CultureInfo.InvariantCulture) + " TimeAttackInfluence bonus float(s). Bonus-delta slots use requested multiplier minus 1. Run a Time Attack XP drop while Luna stays attached.");
				return;
			}
		}
		throw new InvalidOperationException("Time Attack XP Multiplier must be 1 or higher.");
	}

	public bool TryReadCurrentTimeAttackXpMultiplier(out float value)
	{
		value = 0f;
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		lock (_timeAttackPatchLock)
		{
			bool timedOut;
			List<TimeAttackFloatCandidate> list = FindTimeAttackInfluenceRecordFloatCandidates(Stopwatch.StartNew(), out timedOut);
			if (list.Count == 0)
			{
				_log("Time Attack XP Multiplier Load Current did not find live ID-record slots" + (timedOut ? " before the safety timeout." : "."));
				return false;
			}
			value = GetTimeAttackDisplayMultiplier(list);
			_log("Time Attack XP Multiplier Load Current cached " + list.Count.ToString(CultureInfo.InvariantCulture) + " live bonus slot(s). Current value: x" + FormatFloatInvariant(value) + ".");
			return true;
		}
	}

	private int RestoreTimeAttackInfluencePatches()
	{
		lock (_timeAttackPatchLock)
		{
			int num = 0;
			for (int num2 = _timeAttackInfluencePatches.Count - 1; num2 >= 0; num2--)
			{
				try
				{
					WriteTimeAttackBytes(_timeAttackInfluencePatches[num2].Address, _timeAttackInfluencePatches[num2].Original);
					num++;
				}
				catch (Exception ex)
				{
					_log("Could not restore Time Attack XP patch at 0x" + _timeAttackInfluencePatches[num2].Address.ToString("X") + ": " + ex.Message);
				}
			}
			_timeAttackInfluencePatches.Clear();
			return num;
		}
	}

	private List<TimeAttackFloatCandidate> FindTimeAttackInfluenceRecordFloatCandidates(Stopwatch scanWatch, out bool timedOut)
	{
		List<TimeAttackFloatCandidate> list = ValidateTimeAttackInfluenceCachedCandidates();
		if (list.Count > 0)
		{
			timedOut = false;
			return list;
		}
		List<TimeAttackFloatCandidate> list2 = ScanTimeAttackInfluenceRecordFloatCandidates(scanWatch, out timedOut);
		if (list2.Count == 0 && !IsTimeAttackRecordScanExpired(scanWatch))
		{
			bool flag = RefreshTimeAttackInfluenceAnchors(scanWatch);
			List<TimeAttackFloatCandidate> list3 = FindTimeAttackInfluenceFloatCandidates();
			if (list3.Count > 0)
			{
				list2 = list3;
				timedOut = flag;
			}
		}
		if (list2.Count > 0)
		{
			_timeAttackInfluenceCachedCandidates.Clear();
			_timeAttackInfluenceCachedCandidates.AddRange(list2);
		}
		return list2;
	}

	private List<TimeAttackFloatCandidate> ValidateTimeAttackInfluenceCachedCandidates()
	{
		List<TimeAttackFloatCandidate> list = new List<TimeAttackFloatCandidate>();
		HashSet<ulong> hashSet = new HashSet<ulong>();
		foreach (TimeAttackFloatCandidate timeAttackInfluenceCachedCandidate in _timeAttackInfluenceCachedCandidates)
		{
			if (timeAttackInfluenceCachedCandidate.Anchor < 16L)
			{
				continue;
			}
			byte[] array = ReadBytes(timeAttackInfluenceCachedCandidate.Anchor - 16L, 160);
			if (array.Length < 128 || !LooksLikeTimeAttackInfluenceRecord(array, 16))
			{
				continue;
			}
			byte[] array2 = ReadBytes(timeAttackInfluenceCachedCandidate.Address, 4);
			if (array2.Length < 4)
			{
				continue;
			}
			float value = BitConverter.ToSingle(array2, 0);
			if (IsTimeAttackRuntimeBonusValue(value) && hashSet.Add(timeAttackInfluenceCachedCandidate.Address))
			{
				list.Add(new TimeAttackFloatCandidate
				{
					Address = timeAttackInfluenceCachedCandidate.Address,
					Anchor = timeAttackInfluenceCachedCandidate.Anchor,
					Value = value,
					PatchMode = timeAttackInfluenceCachedCandidate.PatchMode
				});
				if (list.Count >= 14)
				{
					break;
				}
			}
		}
		if (list.Count == 0)
		{
			_timeAttackInfluenceCachedCandidates.Clear();
		}
		return list;
	}

	private List<TimeAttackFloatCandidate> ScanTimeAttackInfluenceRecordFloatCandidates(Stopwatch scanWatch, out bool timedOut)
	{
		timedOut = false;
		List<TimeAttackFloatCandidate> candidates = new List<TimeAttackFloatCandidate>();
		HashSet<ulong> seen = new HashSet<ulong>();
		object gate = new object();
		int timedOutFlag = 0;
		int foundEnough = 0;
		List<MemoryRegion> source = EnumerateTimeAttackRecordRegions();
		ParallelOptions parallelOptions = new ParallelOptions();
		parallelOptions.MaxDegreeOfParallelism = Math.Max(1, Math.Min(Environment.ProcessorCount, 6));
		ParallelOptions parallelOptions2 = parallelOptions;
		Parallel.ForEach(source, parallelOptions2, delegate(MemoryRegion region, ParallelLoopState state)
		{
			if (Volatile.Read(ref foundEnough) != 0)
			{
				state.Stop();
			}
			else
			{
				ulong num = 0uL;
				while (num < region.RegionSize && Volatile.Read(ref foundEnough) == 0)
				{
					if (IsTimeAttackRecordScanExpired(scanWatch))
					{
						Interlocked.Exchange(ref timedOutFlag, 1);
						state.Stop();
						break;
					}
					int length = (int)Math.Min(4194560uL, region.RegionSize - num);
					byte[] array = ReadBytes(region.BaseAddress + num, length);
					if (array.Length == 0)
					{
						break;
					}
					ScanTimeAttackRecordChunk(region.BaseAddress + num, array, candidates, seen, gate);
					lock (gate)
					{
						if (candidates.Count >= 14)
						{
							Interlocked.Exchange(ref foundEnough, 1);
							state.Stop();
							break;
						}
					}
					num = ((array.Length > 256) ? (num + (ulong)(array.Length - 256)) : (num + (ulong)array.Length));
				}
			}
		});
		timedOut = Volatile.Read(ref timedOutFlag) != 0;
		return candidates;
	}

	private void ScanTimeAttackRecordChunk(ulong baseAddress, byte[] data, List<TimeAttackFloatCandidate> candidates, HashSet<ulong> seen, object gate)
	{
		foreach (int item in Pattern.FindBytes(data, TimeAttackRecordNeedle, 256))
		{
			int num = item + 16;
			if (!LooksLikeTimeAttackInfluenceRecord(data, num))
			{
				continue;
			}
			lock (gate)
			{
				if (candidates.Count >= 14)
				{
					break;
				}
				AddTimeAttackRecordFloatCandidate((ulong)((long)baseAddress + (long)num + 80L), baseAddress + (ulong)num, data, num + 80, candidates, seen);
				if (candidates.Count >= 14)
				{
					break;
				}
				AddTimeAttackRecordFloatCandidate((ulong)((long)baseAddress + (long)num + 92L), baseAddress + (ulong)num, data, num + 92, candidates, seen);
			}
		}
	}

	private void AddTimeAttackRecordFloatCandidate(ulong address, ulong recordAddress, byte[] data, int offset, List<TimeAttackFloatCandidate> candidates, HashSet<ulong> seen)
	{
		if (candidates.Count < 14 && offset >= 0 && offset + 4 <= data.Length)
		{
			float value = BitConverter.ToSingle(data, offset);
			if (IsTimeAttackRuntimeBonusValue(value) && seen.Add(address))
			{
				candidates.Add(new TimeAttackFloatCandidate
				{
					Address = address,
					Value = value,
					Anchor = recordAddress,
					PatchMode = 1
				});
			}
		}
	}

	private bool IsLiveTimeAttackCandidate(TimeAttackFloatCandidate candidate)
	{
		if (candidate.Anchor < 16L)
		{
			return false;
		}
		try
		{
			byte[] array = ReadBytes(candidate.Anchor - 16L, 160);
			return array.Length >= 128 && LooksLikeTimeAttackInfluenceRecord(array, 16);
		}
		catch
		{
			return false;
		}
	}

	private List<MemoryRegion> EnumerateTimeAttackRecordRegions()
	{
		List<MemoryRegion> list = new List<MemoryRegion>();
		ulong num = 0uL;
		UIntPtr dwLength = (UIntPtr)(ulong)Marshal.SizeOf(typeof(Native.MemoryBasicInformation64));
		while (num < 140737488355327L)
		{
			Native.MemoryBasicInformation64 lpBuffer;
			UIntPtr uIntPtr = Native.VirtualQueryEx(_handle, new UIntPtr(num), out lpBuffer, dwLength);
			if (uIntPtr == UIntPtr.Zero)
			{
				break;
			}
			ulong num2 = lpBuffer.BaseAddress + lpBuffer.RegionSize;
			if (num2 <= num)
			{
				num2 = num + 4096L;
			}
			if (lpBuffer.State == 4096 && IsTimeAttackRecordRegion(lpBuffer.Protect, lpBuffer.BaseAddress, lpBuffer.RegionSize))
			{
				list.Add(new MemoryRegion
				{
					BaseAddress = lpBuffer.BaseAddress,
					RegionSize = lpBuffer.RegionSize
				});
			}
			num = num2;
		}
		list.Sort(CompareTimeAttackRecordRegions);
		return list;
	}

	private static int CompareTimeAttackRecordRegions(MemoryRegion left, MemoryRegion right)
	{
		int num = TimeAttackRecordRegionScore(right);
		int value = TimeAttackRecordRegionScore(left);
		int num2 = num.CompareTo(value);
		if (num2 != 0)
		{
			return num2;
		}
		return right.BaseAddress.CompareTo(left.BaseAddress);
	}

	private static int TimeAttackRecordRegionScore(MemoryRegion region)
	{
		int num = 0;
		if (region.RegionSize >= 16777216L && region.RegionSize <= 67108864L)
		{
			num += 4;
		}
		if (region.RegionSize == 33554432L)
		{
			num += 2;
		}
		if (region.BaseAddress >= 1236950581248L && region.BaseAddress <= 1374389534720L)
		{
			num++;
		}
		return num;
	}

	private static bool IsTimeAttackRecordRegion(uint protect, ulong baseAddress, ulong regionSize)
	{
		if ((protect & 0x100) != 0)
		{
			return false;
		}
		if ((protect & 1) != 0)
		{
			return false;
		}
		if ((protect & 0xFF) != 4)
		{
			return false;
		}
		if ((protect & 0x400) == 0)
		{
			return false;
		}
		if (baseAddress > 1099511627776L && baseAddress < 123145302310912L)
		{
			if (regionSize > 4096L)
			{
				return regionSize <= 67108864L;
			}
			return false;
		}
		return false;
	}

	private static bool LooksLikeTimeAttackInfluenceRecord(byte[] data, int offset)
	{
		if (offset >= 16 && offset + 108 < data.Length)
		{
			if (BitConverter.ToInt32(data, offset) == 87 && BitConverter.ToInt32(data, offset + 24) == 88 && BitConverter.ToInt32(data, offset - 16) == 6 && BitConverter.ToInt32(data, offset - 12) == 2 && BitConverter.ToInt32(data, offset - 8) == 6 && BitConverter.ToInt32(data, offset - 4) == 2 && IsBetween(BitConverter.ToInt32(data, offset + 8), 140, 160) && IsBetween(BitConverter.ToInt32(data, offset + 12), 140, 160) && IsFloatNear(data, offset + 56, 1f) && IsFloatNear(data, offset + 60, 1f) && IsFloatNear(data, offset + 68, 0.5f) && IsFloatNear(data, offset + 76, 2f) && IsTimeAttackRuntimeBonusAt(data, offset + 80) && IsFloatNear(data, offset + 84, 2f) && IsFloatNear(data, offset + 88, 1f) && IsTimeAttackRuntimeBonusAt(data, offset + 92))
			{
				return IsFloatNear(data, offset + 96, 0.4f);
			}
			return false;
		}
		return false;
	}

	private static int ReadInt32Local(byte[] data, int offset)
	{
		return BitConverter.ToInt32(data, offset);
	}

	private static bool IsBetween(int value, int min, int max)
	{
		if (value >= min)
		{
			return value <= max;
		}
		return false;
	}

	private static bool IsFloatNear(byte[] data, int offset, float expected)
	{
		if (offset >= 0 && offset + 4 <= data.Length)
		{
			return Math.Abs(BitConverter.ToSingle(data, offset) - expected) < 0.0005f;
		}
		return false;
	}

	private static bool IsTimeAttackRuntimeBonusAt(byte[] data, int offset)
	{
		if (offset >= 0 && offset + 4 <= data.Length)
		{
			return IsTimeAttackRuntimeBonusValue(BitConverter.ToSingle(data, offset));
		}
		return false;
	}

	private bool RefreshTimeAttackInfluenceAnchors(Stopwatch scanWatch)
	{
		_timeAttackInfluenceStringAddresses.Clear();
		_timeAttackInfluenceReferenceAddresses.Clear();
		bool flag = false;
		byte[][] array = new byte[2][]
		{
			Encoding.ASCII.GetBytes("TimeAttackInfluence"),
			Encoding.ASCII.GetBytes("TimeAttackInfluenceConsumable")
		};
		foreach (MemoryRegion item3 in EnumerateReadableRegions())
		{
			if (!IsTimeAttackScanExpired(scanWatch))
			{
				int length = (int)Math.Min(item3.RegionSize, 33554432uL);
				byte[] array2 = ReadBytes(item3.BaseAddress, length);
				if (array2.Length == 0)
				{
					continue;
				}
				byte[][] array3 = array;
				foreach (byte[] needle in array3)
				{
					foreach (int item4 in Pattern.FindBytes(array2, needle, 32))
					{
						ulong item = item3.BaseAddress + (ulong)item4;
						if (!_timeAttackInfluenceStringAddresses.Contains(item))
						{
							_timeAttackInfluenceStringAddresses.Add(item);
						}
						if (_timeAttackInfluenceStringAddresses.Count >= 32)
						{
							break;
						}
					}
					if (_timeAttackInfluenceStringAddresses.Count >= 32)
					{
						break;
					}
				}
				if (_timeAttackInfluenceStringAddresses.Count >= 32)
				{
					break;
				}
				continue;
			}
			flag = true;
			break;
		}
		if (_timeAttackInfluenceStringAddresses.Count == 0)
		{
			if (!flag)
			{
				return IsTimeAttackScanExpired(scanWatch);
			}
			return true;
		}
		List<byte[]> list = _timeAttackInfluenceStringAddresses.Select((ulong address) => BitConverter.GetBytes(address)).ToList();
		foreach (MemoryRegion item5 in EnumerateReadableRegions())
		{
			if (!IsTimeAttackScanExpired(scanWatch))
			{
				int length2 = (int)Math.Min(item5.RegionSize, 33554432uL);
				byte[] array4 = ReadBytes(item5.BaseAddress, length2);
				if (array4.Length == 0)
				{
					continue;
				}
				foreach (byte[] item6 in list)
				{
					foreach (int item7 in Pattern.FindBytes(array4, item6, 64))
					{
						ulong item2 = item5.BaseAddress + (ulong)item7;
						if (!_timeAttackInfluenceReferenceAddresses.Contains(item2))
						{
							_timeAttackInfluenceReferenceAddresses.Add(item2);
						}
						if (_timeAttackInfluenceReferenceAddresses.Count >= 128)
						{
							break;
						}
					}
					if (_timeAttackInfluenceReferenceAddresses.Count >= 128)
					{
						break;
					}
				}
				if (_timeAttackInfluenceReferenceAddresses.Count >= 128)
				{
					break;
				}
				continue;
			}
			flag = true;
			break;
		}
		if (!flag)
		{
			return IsTimeAttackScanExpired(scanWatch);
		}
		return true;
	}

	private List<TimeAttackFloatCandidate> FindTimeAttackInfluenceFloatCandidates()
	{
		List<TimeAttackFloatCandidate> list = new List<TimeAttackFloatCandidate>();
		HashSet<ulong> seen = new HashSet<ulong>();
		foreach (ulong timeAttackInfluenceStringAddress in _timeAttackInfluenceStringAddresses)
		{
			AddTimeAttackFloatCandidates(timeAttackInfluenceStringAddress, 16384, list, seen);
		}
		foreach (ulong timeAttackInfluenceReferenceAddress in _timeAttackInfluenceReferenceAddresses)
		{
			AddTimeAttackFloatCandidates(timeAttackInfluenceReferenceAddress, 16384, list, seen);
		}
		return list;
	}

	private void AddTimeAttackFloatCandidates(ulong anchor, int radius, List<TimeAttackFloatCandidate> candidates, HashSet<ulong> seen)
	{
		UIntPtr dwLength = (UIntPtr)(ulong)Marshal.SizeOf(typeof(Native.MemoryBasicInformation64));
		Native.MemoryBasicInformation64 lpBuffer;
		UIntPtr uIntPtr = Native.VirtualQueryEx(_handle, new UIntPtr(anchor), out lpBuffer, dwLength);
		if (uIntPtr == UIntPtr.Zero || lpBuffer.State != 4096 || !Native.IsReadable(lpBuffer.Protect))
		{
			return;
		}
		ulong baseAddress = lpBuffer.BaseAddress;
		ulong num = lpBuffer.BaseAddress + lpBuffer.RegionSize;
		ulong num2 = ((anchor > (ulong)radius) ? (anchor - (ulong)radius) : baseAddress);
		if (num2 < baseAddress)
		{
			num2 = baseAddress;
		}
		ulong num3 = anchor + (ulong)radius;
		if (num3 > num)
		{
			num3 = num;
		}
		if (num3 <= num2 || num3 - num2 > 131072L)
		{
			return;
		}
		byte[] array = ReadBytes(num2, (int)(num3 - num2));
		if (array.Length < 4)
		{
			return;
		}
		int num4 = (int)((4L - (num2 & 3L)) & 3L);
		for (int i = num4; i + 4 <= array.Length; i += 4)
		{
			float num5 = BitConverter.ToSingle(array, i);
			if (IsTimeAttackBonusFloat(num5))
			{
				ulong num6 = num2 + (ulong)i;
				if (seen.Add(num6))
				{
					candidates.Add(new TimeAttackFloatCandidate
					{
						Address = num6,
						Value = num5,
						Anchor = anchor,
						PatchMode = ((Math.Abs(num5 - 0.2f) < 0.0005f) ? 1 : 0)
					});
				}
			}
		}
	}

	private static float GetTimeAttackPatchValue(float requestedMultiplier, int patchMode)
	{
		if (patchMode == 1)
		{
			return Math.Max(0f, requestedMultiplier - 1f);
		}
		return requestedMultiplier;
	}

	private static float GetTimeAttackDisplayMultiplier(IEnumerable<TimeAttackFloatCandidate> candidates)
	{
		List<float> list = new List<float>();
		foreach (TimeAttackFloatCandidate candidate in candidates)
		{
			float num = ((candidate.PatchMode == 1) ? (candidate.Value + 1f) : candidate.Value);
			if (!float.IsNaN(num) && !float.IsInfinity(num) && num > 0f)
			{
				list.Add(num);
			}
		}
		if (list.Count == 0)
		{
			return 1f;
		}
		list.Sort();
		return list[list.Count / 2];
	}

	private List<MemoryRegion> EnumerateReadableRegions()
	{
		List<MemoryRegion> list = new List<MemoryRegion>();
		ulong num = 0uL;
		UIntPtr dwLength = (UIntPtr)(ulong)Marshal.SizeOf(typeof(Native.MemoryBasicInformation64));
		while (num < 140737488355327L)
		{
			Native.MemoryBasicInformation64 lpBuffer;
			UIntPtr uIntPtr = Native.VirtualQueryEx(_handle, new UIntPtr(num), out lpBuffer, dwLength);
			if (uIntPtr == UIntPtr.Zero)
			{
				break;
			}
			ulong num2 = lpBuffer.BaseAddress + lpBuffer.RegionSize;
			if (num2 <= num)
			{
				num2 = num + 4096L;
			}
			if (lpBuffer.State == 4096 && Native.IsReadable(lpBuffer.Protect) && lpBuffer.RegionSize > 4096L && lpBuffer.RegionSize <= 134217728L)
			{
				list.Add(new MemoryRegion
				{
					BaseAddress = lpBuffer.BaseAddress,
					RegionSize = lpBuffer.RegionSize
				});
			}
			num = num2;
		}
		return list;
	}

	private static bool IsTimeAttackBonusFloat(float value)
	{
		if (!(Math.Abs(value - 1.2f) < 0.0005f))
		{
			return Math.Abs(value - 0.2f) < 0.0005f;
		}
		return true;
	}

	private static bool IsTimeAttackRuntimeBonusValue(float value)
	{
		if (!float.IsNaN(value) && !float.IsInfinity(value) && value >= 0f)
		{
			return value <= 1000000f;
		}
		return false;
	}

	private static bool IsTimeAttackScanExpired(Stopwatch scanWatch)
	{
		if (scanWatch != null)
		{
			return scanWatch.ElapsedMilliseconds >= 5000L;
		}
		return false;
	}

	private static bool IsTimeAttackRecordScanExpired(Stopwatch scanWatch)
	{
		if (scanWatch != null)
		{
			return scanWatch.ElapsedMilliseconds >= 10000L;
		}
		return false;
	}

	private static string FormatFloatInvariant(float value)
	{
		return value.ToString("0.###", CultureInfo.InvariantCulture);
	}

	public bool TryReadLiveProfileXpLevel(out int value)
	{
		value = 0;
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		List<LiveProfileIntegerMatch> list = (from item in FindPrimaryLiveProfileXpBackingFields()
			where IsXpProfileBackingKey(item.Key)
			group item by item.Address into @group
			select @group.First()).ToList();
		if (list.Count == 0)
		{
			return false;
		}
		list.Sort(delegate(LiveProfileIntegerMatch left, LiveProfileIntegerMatch right)
		{
			int num = XpFieldPriority(left.Key).CompareTo(XpFieldPriority(right.Key));
			return (num != 0) ? num : left.Address.CompareTo(right.Address);
		});
		lock (_xpBackingLock)
		{
			_xpBackingMatches = list;
		}
		LiveProfileIntegerMatch liveProfileIntegerMatch = (from m in list
			orderby m.BufferLength descending, XpFieldPriority(m.Key)
			select m).First();
		value = liveProfileIntegerMatch.Value;
		_log("Live Xp Value loaded from active profile field " + liveProfileIntegerMatch.Key + " at 0x" + liveProfileIntegerMatch.Address.ToString("X") + ": " + value.ToString(CultureInfo.InvariantCulture));
		return true;
	}

	public bool TryReadXpAggregateCurrentValue(out int value)
	{
		value = 0;
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		RuntimeProfileHookDescriptor xpAggregateDescriptor = GetXpAggregateDescriptor();
		RuntimeDetour value2;
		lock (_runtimePatchLock)
		{
			_runtimeProfileHooks.TryGetValue(xpAggregateDescriptor.Key, out value2);
		}
		if (value2 != null && value2.DetourAddress != 0L)
		{
			if (xpAggregateDescriptor.CaptureOffset >= 0)
			{
				int num = method_1(value2.DetourAddress + (ulong)xpAggregateDescriptor.CaptureOffset);
				if (num > 0)
				{
					value = num;
					return true;
				}
			}
			if (xpAggregateDescriptor.ObjectPointerOffset >= 0)
			{
				ulong num2 = method_0(value2.DetourAddress + (ulong)xpAggregateDescriptor.ObjectPointerOffset);
				if (num2 != 0L)
				{
					int num3 = method_1(num2 + 140L);
					if (num3 > 0)
					{
						value = num3;
						return true;
					}
				}
			}
			return false;
		}
		return false;
	}

	public int MaintainLiveProfileXpLevel(int value, bool forceRefresh)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		lock (_xpBackingLock)
		{
			if (forceRefresh || _xpBackingMatches.Count == 0)
			{
				_log("Refreshing XP Value writable profile field list.");
				_xpBackingMatches = FindLiveProfileXpBackingFields(value);
			}
			if (_xpBackingMatches.Count == 0)
			{
				throw new InvalidOperationException("XP backing fields were not found in live profile memory.");
			}
			int num = WriteXpBackingFields(value, _xpBackingMatches, forceWrite: false);
			if (num < 0)
			{
				_log("Xp Value backing field list moved; refreshing writable BXML field list.");
				_xpBackingMatches = FindLiveProfileXpBackingFields(value);
				if (_xpBackingMatches.Count == 0)
				{
					throw new InvalidOperationException("XP backing fields were not found in live profile memory.");
				}
				num = WriteXpBackingFields(value, _xpBackingMatches, forceWrite: false);
				if (num < 0)
				{
					num = 0;
				}
			}
			return num;
		}
	}

	private void RefreshLiveProfileXpBackingFieldsOrThrow(int value)
	{
		lock (_xpBackingLock)
		{
			_log("Refreshing XP Value writable profile field list.");
			_xpBackingMatches = FindLiveProfileXpBackingFields(value);
			if (_xpBackingMatches.Count == 0)
			{
				throw new InvalidOperationException("XP backing fields were not found in live profile memory. Open the in-game garage/profile screen, press Load Current, then apply XP again.");
			}
		}
	}

	private List<LiveProfileIntegerMatch> FindLiveProfileXpBackingFields(int targetValue)
	{
		List<LiveProfileIntegerMatch> source = FindPrimaryLiveProfileXpBackingFields();
		source = (from match in source
			where IsXpProfileBackingKey(match.Key)
			group match by match.Address into @group
			select @group.First()).ToList();
		source.Sort(delegate(LiveProfileIntegerMatch left, LiveProfileIntegerMatch right)
		{
			int num = XpFieldPriority(left.Key).CompareTo(XpFieldPriority(right.Key));
			return (num != 0) ? num : left.Address.CompareTo(right.Address);
		});
		if (source.Count > 0)
		{
			string text = string.Join(", ", (from @group in source.GroupBy((LiveProfileIntegerMatch match) => match.Key, StringComparer.OrdinalIgnoreCase)
				select @group.Key + "=" + @group.Count().ToString(CultureInfo.InvariantCulture)).ToArray());
			_log("XP Value writable backing fields found: " + text + ".");
		}
		return source;
	}

	private void AddRawProgressionValueMatches(List<LiveProfileIntegerMatch> matches, HashSet<ulong> seen, int targetValue)
	{
		List<int> list = (from match in matches
			where (match.Key.Equals("WristbandLevel", StringComparison.OrdinalIgnoreCase) || match.Key.Equals("TotalSkills", StringComparison.OrdinalIgnoreCase) || match.Key.Equals("XP", StringComparison.OrdinalIgnoreCase)) && match.Value > 0 && match.Value != targetValue
			select match.Value).Distinct().Take(4).ToList();
		if (list.Count == 0)
		{
			return;
		}
		byte[][] needles = new byte[4][]
		{
			Encoding.ASCII.GetBytes("TotalSkills"),
			Encoding.ASCII.GetBytes("WristbandLevel"),
			Encoding.ASCII.GetBytes("Main/TotalSkills"),
			Encoding.ASCII.GetBytes("CompareStats/WristbandLevel")
		};
		foreach (MemoryRegion item in EnumerateReadableWritableRegions())
		{
			if (item.RegionSize > 67108864L)
			{
				continue;
			}
			int length = checked((int)item.RegionSize);
			byte[] array = ReadBytes(item.BaseAddress, length);
			if (array.Length == 0 || !ContainsAny(array, needles))
			{
				continue;
			}
			foreach (int item2 in list)
			{
				AddRawProgressionNeedleMatches(matches, seen, item.BaseAddress, array, BitConverter.GetBytes((long)item2), 8);
				AddRawProgressionNeedleMatches(matches, seen, item.BaseAddress, array, BitConverter.GetBytes(item2), 4);
			}
		}
	}

	private static bool ContainsAny(byte[] data, IEnumerable<byte[]> needles)
	{
		foreach (byte[] needle in needles)
		{
			if (IndexOf(data, needle, 0) >= 0)
			{
				return true;
			}
		}
		return false;
	}

	private static void AddRawProgressionNeedleMatches(List<LiveProfileIntegerMatch> matches, HashSet<ulong> seen, ulong baseAddress, byte[] data, byte[] needle, int size)
	{
		for (int num = IndexOf(data, needle, 0); num >= 0; num = IndexOf(data, needle, num + 1))
		{
			ulong num2 = baseAddress + (ulong)num;
			if (seen.Add(num2))
			{
				int value = (int)((size == 8) ? BitConverter.ToInt64(data, num) : BitConverter.ToInt32(data, num));
				matches.Add(new LiveProfileIntegerMatch
				{
					BaseAddress = baseAddress,
					Address = num2,
					BufferLength = data.Length,
					Offset = num,
					Value = value,
					Key = "RawProgression",
					Size = size,
					Score = 90000000 + num
				});
			}
		}
	}

	private void AddProfileIntegerMatches(List<LiveProfileIntegerMatch> matches, HashSet<ulong> seen, ulong baseAddress, byte[] data, string[] keys, int minValue, int maxValue, int bufferLength)
	{
		foreach (LiveProfileIntegerMatch item in LocateProfileIntegerFields(data, keys, minValue, maxValue))
		{
			ulong num = baseAddress + (ulong)item.Offset;
			if (seen.Add(num))
			{
				item.BaseAddress = baseAddress;
				item.Address = num;
				item.BufferLength = bufferLength;
				matches.Add(item);
			}
		}
	}

	private void AddGlobalBxmlIntegerMatches(List<LiveProfileIntegerMatch> matches, HashSet<ulong> seen, string[] keys, int minValue, int maxValue)
	{
		byte[][] needles = new byte[1][] { Encoding.ASCII.GetBytes("Credits") };
		byte[][] needles2 = new byte[3][]
		{
			Encoding.ASCII.GetBytes("TotalXP"),
			Encoding.ASCII.GetBytes("WristbandLevel"),
			Encoding.ASCII.GetBytes("TotalSkills")
		};
		foreach (MemoryRegion item in EnumerateReadableWritableRegions())
		{
			ulong num = item.BaseAddress;
			ulong num2 = item.RegionSize;
			byte[] array = new byte[0];
			while (num2 > 0L)
			{
				int num3 = (int)Math.Min(4194304uL, num2);
				byte[] array2 = ReadBytes(num, num3);
				if (array2.Length > 0)
				{
					byte[] array3 = new byte[array.Length + array2.Length];
					Buffer.BlockCopy(array, 0, array3, 0, array.Length);
					Buffer.BlockCopy(array2, 0, array3, array.Length, array2.Length);
					ulong baseAddress = num - (ulong)array.Length;
					int bufferLength = (int)((item.RegionSize > 2147483647L) ? int.MaxValue : item.RegionSize);
					if (ContainsAny(array3, needles) && ContainsAny(array3, needles2))
					{
						AddProfileIntegerMatches(matches, seen, baseAddress, array3, keys, minValue, maxValue, bufferLength);
					}
					int num4 = Math.Min(256, array3.Length);
					array = new byte[num4];
					Buffer.BlockCopy(array3, array3.Length - num4, array, 0, num4);
				}
				else
				{
					array = new byte[0];
				}
				num += (ulong)num3;
				num2 -= (ulong)num3;
			}
		}
	}

	private List<LiveProfileIntegerMatch> FindPrimaryLiveProfileXpBackingFields()
	{
		List<LiveProfileIntegerMatch> list = new List<LiveProfileIntegerMatch>();
		HashSet<ulong> seen = new HashSet<ulong>();
		foreach (LiveProfileCandidate item in FindLiveProfileCandidates(12))
		{
			AddProfileIntegerMatches(list, seen, item.BaseAddress, item.Data, GetXpProfileBackingKeys(), 0, int.MaxValue, item.Data.Length);
		}
		return list;
	}

	private int WriteXpBackingFields(int value, IEnumerable<LiveProfileIntegerMatch> matches, bool forceWrite)
	{
		int num = 0;
		foreach (LiveProfileIntegerMatch match in matches)
		{
			byte[] array = ReadBytes(match.Address, match.Size);
			if (array.Length >= match.Size)
			{
				long num2 = ((match.Size == 8) ? BitConverter.ToInt64(array, 0) : BitConverter.ToInt32(array, 0));
				if (forceWrite || num2 != value)
				{
					byte[] data = ((match.Size == 8) ? BitConverter.GetBytes((long)value) : BitConverter.GetBytes(value));
					WriteBytes(match.Address, data);
					num++;
				}
				continue;
			}
			return -1;
		}
		return num;
	}

	private static int XpFieldPriority(string key)
	{
		if (key.Equals("WristbandLevel", StringComparison.OrdinalIgnoreCase))
		{
			return 0;
		}
		if (key.Equals("TotalSkills", StringComparison.OrdinalIgnoreCase))
		{
			return 1;
		}
		if (key.Equals("XP", StringComparison.OrdinalIgnoreCase))
		{
			return 2;
		}
		if (key.Equals("TotalXP", StringComparison.OrdinalIgnoreCase))
		{
			return 3;
		}
		if (key.Equals("Main/TotalXP", StringComparison.OrdinalIgnoreCase))
		{
			return 4;
		}
		if (key.Equals("Level", StringComparison.OrdinalIgnoreCase))
		{
			return 5;
		}
		return 100;
	}

	private static string[] GetXpProfileReadKeys()
	{
		return new string[6] { "WristbandLevel", "TotalSkills", "XP", "TotalXP", "Main/TotalXP", "Level" };
	}

	private static string[] GetXpProfileBackingKeys()
	{
		return new string[6] { "WristbandLevel", "TotalSkills", "XP", "TotalXP", "Main/TotalXP", "Level" };
	}

	private static bool IsXpProfileBackingKey(string key)
	{
		if (string.IsNullOrEmpty(key))
		{
			return false;
		}
		if (!key.Equals("TotalXP", StringComparison.OrdinalIgnoreCase) && !key.Equals("Main/TotalXP", StringComparison.OrdinalIgnoreCase) && !key.Equals("XP", StringComparison.OrdinalIgnoreCase) && !key.Equals("WristbandLevel", StringComparison.OrdinalIgnoreCase) && !key.Equals("TotalSkills", StringComparison.OrdinalIgnoreCase))
		{
			return key.Equals("Level", StringComparison.OrdinalIgnoreCase);
		}
		return true;
	}

	private List<LiveProfileIntegerMatch> FindLiveProfileIntegerMatches(string[] keys, int maxCandidates)
	{
		List<LiveProfileIntegerMatch> list = new List<LiveProfileIntegerMatch>();
		foreach (LiveProfileCandidate item in FindLiveProfileCandidates(maxCandidates))
		{
			LiveProfileIntegerMatch liveProfileIntegerMatch = LocateProfileIntegerField(item.Data, keys, 0, int.MaxValue);
			if (liveProfileIntegerMatch.Offset >= 0)
			{
				liveProfileIntegerMatch.BaseAddress = item.BaseAddress;
				liveProfileIntegerMatch.Address = item.BaseAddress + (ulong)liveProfileIntegerMatch.Offset;
				liveProfileIntegerMatch.BufferLength = item.Data.Length;
				list.Add(liveProfileIntegerMatch);
			}
		}
		return list;
	}

	private List<LiveProfileCandidate> FindLiveProfileCandidates(int maxCandidates)
	{
		List<LiveProfileCandidate> list = new List<LiveProfileCandidate>();
		List<MemoryRegion> list2 = EnumerateReadableWritableRegions();
		list2.Sort((MemoryRegion a, MemoryRegion b) => b.BaseAddress.CompareTo(a.BaseAddress));
		byte[] bytes = Encoding.ASCII.GetBytes("MouseControlOptions");
		Stopwatch scanWatch = Stopwatch.StartNew();
		foreach (MemoryRegion item in list2)
		{
			if (IsXpProfileCandidateScanExpired(scanWatch))
			{
				break;
			}
			using IEnumerator<LiveProfileCandidate> enumerator2 = ScanRegionForLiveProfiles(item, bytes, scanWatch).GetEnumerator();
			while (enumerator2.MoveNext())
			{
				Func<LiveProfileCandidate, bool> func = null;
				LiveProfileCandidate candidate = enumerator2.Current;
				func = (LiveProfileCandidate c) => c.BaseAddress == candidate.BaseAddress;
				if (!list.Any(func))
				{
					list.Add(candidate);
					if (list.Count >= maxCandidates)
					{
						return list;
					}
				}
			}
		}
		if (list.Count < maxCandidates)
		{
			foreach (MemoryRegion item2 in list2)
			{
				if (IsXpProfileCandidateScanExpired(scanWatch))
				{
					break;
				}
				using IEnumerator<LiveProfileCandidate> enumerator4 = ScanRegionForProfileHeaders(item2, scanWatch).GetEnumerator();
				while (enumerator4.MoveNext())
				{
					Func<LiveProfileCandidate, bool> func2 = null;
					LiveProfileCandidate candidate2 = enumerator4.Current;
					func2 = (LiveProfileCandidate c) => c.BaseAddress == candidate2.BaseAddress;
					if (!list.Any(func2))
					{
						list.Add(candidate2);
						if (list.Count >= maxCandidates)
						{
							return list;
						}
					}
				}
			}
		}
		return list;
	}

	private IEnumerable<LiveProfileCandidate> ScanRegionForLiveProfiles(MemoryRegion region, byte[] marker, Stopwatch scanWatch)
	{
		ulong current = region.BaseAddress;
		ulong remaining = region.RegionSize;
		byte[] carry = new byte[0];
		while (remaining > 0L && !IsXpProfileCandidateScanExpired(scanWatch))
		{
			int chunkSize = (int)Math.Min(4194304uL, remaining);
			byte[] read = ReadBytes(current, chunkSize);
			if (read.Length > 0)
			{
				byte[] data = new byte[carry.Length + read.Length];
				Buffer.BlockCopy(carry, 0, data, 0, carry.Length);
				Buffer.BlockCopy(read, 0, data, carry.Length, read.Length);
				ulong dataBase = current - (ulong)carry.Length;
				for (int at = IndexOf(data, marker, 0); at >= 0; at = IndexOf(data, marker, at + 1))
				{
					int profileOffset = at - 21;
					if (profileOffset >= 0 && profileOffset + 12 < data.Length && BitConverter.ToUInt32(data, profileOffset) == ForzaProfileHash("profile"))
					{
						ulong baseAddress = dataBase + (ulong)profileOffset;
						LiveProfileCandidate candidate = TryReadLiveProfileCandidate(baseAddress, BitConverter.ToUInt32(data, profileOffset + 4));
						if (candidate != null)
						{
							yield return candidate;
						}
					}
				}
				int keep = Math.Min(36864, data.Length);
				carry = new byte[keep];
				Buffer.BlockCopy(data, data.Length - keep, carry, 0, keep);
			}
			current += (ulong)chunkSize;
			remaining -= (ulong)chunkSize;
		}
	}

	private IEnumerable<LiveProfileCandidate> ScanRegionForProfileHeaders(MemoryRegion region, Stopwatch scanWatch)
	{
		byte[] profileHash = BitConverter.GetBytes(ForzaProfileHash("profile"));
		ulong current = region.BaseAddress;
		ulong remaining = region.RegionSize;
		byte[] carry = new byte[0];
		while (remaining > 0L && !IsXpProfileCandidateScanExpired(scanWatch))
		{
			int chunkSize = (int)Math.Min(4194304uL, remaining);
			byte[] read = ReadBytes(current, chunkSize);
			if (read.Length <= 0)
			{
				carry = new byte[0];
			}
			else
			{
				byte[] data = new byte[carry.Length + read.Length];
				Buffer.BlockCopy(carry, 0, data, 0, carry.Length);
				Buffer.BlockCopy(read, 0, data, carry.Length, read.Length);
				ulong dataBase = current - (ulong)carry.Length;
				for (int at = IndexOf(data, profileHash, 0); at >= 0; at = IndexOf(data, profileHash, at + 1))
				{
					if (at >= 0 && at + 8 <= data.Length)
					{
						uint profileSize = BitConverter.ToUInt32(data, at + 4);
						ulong baseAddress = dataBase + (ulong)at;
						LiveProfileCandidate candidate = TryReadLiveProfileCandidate(baseAddress, profileSize);
						if (candidate != null)
						{
							yield return candidate;
						}
					}
				}
				int keep = Math.Min(16, data.Length);
				carry = new byte[keep];
				Buffer.BlockCopy(data, data.Length - keep, carry, 0, keep);
			}
			current += (ulong)chunkSize;
			remaining -= (ulong)chunkSize;
		}
	}

	private LiveProfileCandidate TryReadLiveProfileCandidate(ulong baseAddress, uint profileSize)
	{
		if (profileSize >= 4096 && profileSize <= 2097152)
		{
			int num = GuessLiveProfileBufferLength(baseAddress, profileSize);
			if (num <= 0)
			{
				return null;
			}
			byte[] array = ReadBytes(baseAddress, num);
			if (array.Length != num)
			{
				return null;
			}
			if (LocateProfileIntegerField(array, new string[1] { "Credits" }, 0, int.MaxValue).Offset < 0)
			{
				return null;
			}
			if (LocateProfileIntegerField(array, GetXpProfileBackingKeys(), 0, int.MaxValue).Offset < 0)
			{
				return null;
			}
			LiveProfileCandidate liveProfileCandidate = new LiveProfileCandidate();
			liveProfileCandidate.BaseAddress = baseAddress;
			liveProfileCandidate.Data = array;
			return liveProfileCandidate;
		}
		return null;
	}

	private static bool IsXpProfileCandidateScanExpired(Stopwatch scanWatch)
	{
		if (scanWatch != null)
		{
			return scanWatch.ElapsedMilliseconds >= 150000L;
		}
		return false;
	}

	private int GuessLiveProfileBufferLength(ulong baseAddress, uint firstSectionSize)
	{
		int val = checked((int)Math.Min(4194304u, firstSectionSize + 4096));
		byte[] array = ReadBytes(baseAddress, Math.Max(val, 262144));
		if (array.Length < 8)
		{
			return 0;
		}
		int num = 0;
		for (int i = 0; i < 8; i++)
		{
			if (num + 8 > array.Length)
			{
				break;
			}
			uint num2 = BitConverter.ToUInt32(array, num);
			uint num3 = BitConverter.ToUInt32(array, num + 4);
			if ((num2 == 0 && num3 == 0) || num3 > 3145728)
			{
				break;
			}
			long num4 = num + 8L + num3;
			checked
			{
				if (num4 > array.Length)
				{
					byte[] array2 = ReadBytes(baseAddress, (int)Math.Min(4194304L, num4 + 4096L));
					if (num4 > array2.Length)
					{
						break;
					}
					array = array2;
				}
				num = (int)num4;
			}
		}
		if (num <= 0)
		{
			return checked((int)(8 + firstSectionSize));
		}
		return num;
	}

	private List<MemoryRegion> EnumerateReadableWritableRegions()
	{
		List<MemoryRegion> list = new List<MemoryRegion>();
		ulong num = 0uL;
		UIntPtr dwLength = (UIntPtr)(ulong)Marshal.SizeOf(typeof(Native.MemoryBasicInformation64));
		while (num < 140737488355327L)
		{
			Native.MemoryBasicInformation64 lpBuffer;
			UIntPtr uIntPtr = Native.VirtualQueryEx(_handle, new UIntPtr(num), out lpBuffer, dwLength);
			if (uIntPtr == UIntPtr.Zero)
			{
				break;
			}
			ulong num2 = lpBuffer.BaseAddress + lpBuffer.RegionSize;
			if (num2 <= num)
			{
				num2 = num + 4096L;
			}
			if (lpBuffer.State == 4096 && IsReadableWritable(lpBuffer.Protect) && lpBuffer.RegionSize > 4096L)
			{
				list.Add(new MemoryRegion
				{
					BaseAddress = lpBuffer.BaseAddress,
					RegionSize = lpBuffer.RegionSize
				});
			}
			num = num2;
		}
		return list;
	}

	private static bool IsReadableWritable(uint protect)
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
		if (num != 4 && num != 8)
		{
			return num == 64;
		}
		return true;
	}

	private static LiveProfileIntegerMatch LocateProfileIntegerField(byte[] data, string[] keys, int minValue, int maxValue)
	{
		LiveProfileIntegerMatch liveProfileIntegerMatch = new LiveProfileIntegerMatch();
		liveProfileIntegerMatch.Offset = -1;
		liveProfileIntegerMatch.Score = int.MaxValue;
		liveProfileIntegerMatch.Size = 4;
		LiveProfileIntegerMatch liveProfileIntegerMatch2 = liveProfileIntegerMatch;
		foreach (LiveProfileIntegerMatch item in LocateProfileIntegerFields(data, keys, minValue, maxValue))
		{
			int num = XpFieldPriority(item.Key) * 1000000 + item.Offset;
			if (num < liveProfileIntegerMatch2.Score)
			{
				item.Score = num;
				liveProfileIntegerMatch2 = item;
			}
		}
		return liveProfileIntegerMatch2;
	}

	private static List<LiveProfileIntegerMatch> LocateProfileIntegerFields(byte[] data, string[] keys, int minValue, int maxValue)
	{
		List<LiveProfileIntegerMatch> list = new List<LiveProfileIntegerMatch>();
		for (int i = 0; i < keys.Length; i++)
		{
			string text = keys[i];
			if (string.IsNullOrWhiteSpace(text) || text.Length < 2)
			{
				continue;
			}
			byte[] bytes = Encoding.ASCII.GetBytes(text);
			for (int num = IndexOf(data, bytes, 0); num >= 0; num = IndexOf(data, bytes, num + 1))
			{
				if (num >= 8 && num + bytes.Length + 8 <= data.Length)
				{
					uint num2 = BitConverter.ToUInt32(data, num - 8);
					uint num3 = BitConverter.ToUInt32(data, num - 4);
					if (num3 == bytes.Length && (num2 == 32 || num2 == 33 || num2 == 65568))
					{
						uint type = BitConverter.ToUInt32(data, num + bytes.Length);
						int num4 = num + bytes.Length + 4;
						if (TryReadProfileInteger(data, num4, type, out var value, out var size) && value >= minValue && value <= maxValue)
						{
							list.Add(new LiveProfileIntegerMatch
							{
								Offset = num4,
								Value = (int)value,
								Key = text,
								Score = i * 1000000 + num,
								Size = size
							});
						}
					}
				}
			}
		}
		return list;
	}

	private static bool TryReadProfileInteger(byte[] data, int valueOffset, uint type, out long value, out int size)
	{
		value = 0L;
		size = 4;
		if (valueOffset >= 0 && valueOffset + 4 <= data.Length)
		{
			switch (type)
			{
			case 4u:
				if (valueOffset + 8 > data.Length)
				{
					return false;
				}
				value = BitConverter.ToInt64(data, valueOffset);
				size = 8;
				return true;
			default:
				return false;
			case 0u:
			case 1u:
			case 3u:
			case 17u:
				value = BitConverter.ToInt32(data, valueOffset);
				size = 4;
				return true;
			}
		}
		return false;
	}

	private static int IndexOf(byte[] data, byte[] needle, int start)
	{
		if (needle.Length != 0 && start <= data.Length - needle.Length)
		{
			byte value = needle[0];
			int num = data.Length - needle.Length;
			int num2 = start;
			while (true)
			{
				if (num2 <= num)
				{
					num2 = Array.IndexOf(data, value, num2, num - num2 + 1);
					if (num2 < 0)
					{
						break;
					}
					bool flag = true;
					for (int i = 0; i < needle.Length; i++)
					{
						if (data[num2 + i] != needle[i])
						{
							flag = false;
							break;
						}
					}
					if (!flag)
					{
						num2++;
						continue;
					}
					return num2;
				}
				return -1;
			}
			return -1;
		}
		return -1;
	}

	private static uint ForzaProfileHash(string text)
	{
		uint num = 5381u;
		for (int i = 0; i < 2; i++)
		{
			for (int j = 0; j < text.Length; j++)
			{
				num ^= text[j] + (num >> 2) + 32 * num;
			}
		}
		return num;
	}

	public List<RuntimeProfileFeature> ArmProfileRuntimeValueCapture(IEnumerable<RuntimeProfileFeature> features)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		List<RuntimeProfileFeature> list = new List<RuntimeProfileFeature>();
		foreach (RuntimeProfileFeature feature in features)
		{
			bool flag = false;
			RuntimeProfileHookDescriptor[] profileHookDescriptors = GetProfileHookDescriptors(feature);
			foreach (RuntimeProfileHookDescriptor runtimeProfileHookDescriptor in profileHookDescriptors)
			{
				try
				{
					if (runtimeProfileHookDescriptor.CaptureOffset >= 0)
					{
						RuntimeDetour runtimeDetour = EnsureRuntimeProfileHook(runtimeProfileHookDescriptor);
						method_2(runtimeDetour.DetourAddress + (ulong)runtimeProfileHookDescriptor.CaptureOffset, int.MinValue);
						flag = true;
					}
				}
				catch (Exception ex)
				{
					_log(string.Concat("Current ", feature, " capture could not be armed: ", ex.Message));
				}
			}
			if (flag)
			{
				list.Add(feature);
			}
		}
		if (list.Count > 0)
		{
			_log("Current runtime capture armed for " + list.Count + " value(s).");
		}
		return list;
	}

	public Dictionary<RuntimeProfileFeature, int> ReadProfileRuntimeCaptureValues(IEnumerable<RuntimeProfileFeature> features, bool logMisses)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		Dictionary<RuntimeProfileFeature, int> dictionary = new Dictionary<RuntimeProfileFeature, int>();
		foreach (RuntimeProfileFeature feature in features)
		{
			RuntimeProfileHookDescriptor[] profileHookDescriptors = GetProfileHookDescriptors(feature);
			foreach (RuntimeProfileHookDescriptor runtimeProfileHookDescriptor in profileHookDescriptors)
			{
				try
				{
					if (runtimeProfileHookDescriptor.CaptureOffset < 0)
					{
						continue;
					}
					RuntimeDetour value;
					lock (_runtimePatchLock)
					{
						if (!_runtimeProfileHooks.TryGetValue(runtimeProfileHookDescriptor.Key, out value))
						{
							continue;
						}
					}
					if (!TryReadRuntimeCaptureValue(value, runtimeProfileHookDescriptor, int.MinValue, out var value2))
					{
						continue;
					}
					dictionary[feature] = value2;
					break;
				}
				catch (Exception ex)
				{
					if (logMisses)
					{
						_log(string.Concat("Current ", feature, " capture could not be read: ", ex.Message));
					}
				}
			}
		}
		if (logMisses)
		{
			_log("Current runtime capture read " + dictionary.Count + " value(s).");
		}
		return dictionary;
	}

	private bool TryReadRuntimeCaptureValue(RuntimeDetour detour, RuntimeProfileHookDescriptor descriptor, int sentinel, out int value)
	{
		value = 0;
		int num = method_1(detour.DetourAddress + (ulong)descriptor.CaptureOffset);
		if (num != sentinel)
		{
			value = num;
			return true;
		}
		if (descriptor.ObjectPointerOffset >= 0 && descriptor.ObjectValueFieldOffset >= 0)
		{
			ulong num2 = method_0(detour.DetourAddress + (ulong)descriptor.ObjectPointerOffset);
			if (num2 != 0L)
			{
				ulong address = num2 + (ulong)descriptor.ObjectValueFieldOffset;
				if (IsReadableMemoryRange(address, 4))
				{
					value = method_1(address);
					return true;
				}
			}
		}
		return false;
	}

	private RuntimeDetour EnsureRuntimeProfileHook(RuntimeProfileHookDescriptor descriptor)
	{
		lock (_runtimePatchLock)
		{
			if (_runtimeProfileHooks.TryGetValue(descriptor.Key, out var value))
			{
				return value;
			}
			EnsureCrcBypass();
			byte[] array = ReadBytes(_mainBase, _mainSize);
			if (array.Length == 0)
			{
				throw new InvalidOperationException("Could not read main module memory for " + descriptor.Name + " hook scan.");
			}
			FindProfileHookTarget(array, descriptor, out var hookAddress, out var _);
			RuntimeDetour runtimeDetour = CreateRuntimeDetour(descriptor, hookAddress);
			_runtimeProfileHooks.Add(descriptor.Key, runtimeDetour);
			_log(descriptor.Name + " runtime detour installed. target=0x" + hookAddress.ToString("X") + ", detour=0x" + runtimeDetour.DetourAddress.ToString("X"));
			return runtimeDetour;
		}
	}

	private void FindProfileHookTarget(byte[] module, RuntimeProfileHookDescriptor descriptor, out ulong hookAddress, out byte[] current)
	{
		hookAddress = 0uL;
		current = null;
		if (!string.IsNullOrEmpty(descriptor.MetadataName))
		{
			int num = FindAsciiOffset(module, descriptor.MetadataName + "\0");
			if (num < 0)
			{
				throw new InvalidOperationException(descriptor.Name + " metadata name was not found: " + descriptor.MetadataName);
			}
			ulong address = (ulong)((long)_mainBase + (long)num + descriptor.MetadataPointerOffset);
			ulong num2 = method_0(address);
			if (num2 == 0L)
			{
				throw new InvalidOperationException(descriptor.Name + " metadata pointer was empty at 0x" + address.ToString("X") + ".");
			}
			byte[] array = ReadBytes(num2, descriptor.HookSize);
			if (array.Length < descriptor.HookSize)
			{
				throw new InvalidOperationException(descriptor.Name + " metadata target could not be read at 0x" + num2.ToString("X") + ".");
			}
			if (!BytesStartWith(array, descriptor.ExpectedOriginal))
			{
				throw new InvalidOperationException(descriptor.Name + " metadata target bytes did not match the expected FH6 sequence. Found: " + FormatBytes(array));
			}
			hookAddress = num2;
			current = array;
			return;
		}
		int[] pattern = Pattern.Parse(descriptor.Signature);
		bool flag = false;
		bool flag2 = false;
		string text = string.Empty;
		foreach (int item in Pattern.FindAll(module, pattern, 128))
		{
			flag = true;
			ulong num5;
			if (descriptor.ResolveCallTarget)
			{
				ulong num3 = _mainBase + (ulong)item;
				byte[] array2 = ReadBytes(num3, 5);
				if (array2.Length < 5 || array2[0] != 232)
				{
					continue;
				}
				int num4 = BitConverter.ToInt32(array2, 1);
				num5 = (ulong)((long)(num3 + 5L) + (long)num4 + descriptor.CallTargetOffset);
			}
			else
			{
				num5 = (ulong)((long)_mainBase + (long)item + descriptor.MatchOffset);
			}
			byte[] array3 = ReadBytes(num5, descriptor.HookSize);
			if (array3.Length >= descriptor.HookSize)
			{
				if (BytesStartWith(array3, descriptor.ExpectedOriginal))
				{
					hookAddress = num5;
					current = array3;
					return;
				}
				if (array3.Length > 0 && array3[0] == 233)
				{
					flag2 = true;
				}
				if (string.IsNullOrEmpty(text))
				{
					text = FormatBytes(array3);
				}
			}
		}
		if (!flag)
		{
			throw new InvalidOperationException(descriptor.Name + " hook signature was not found. Signature: " + descriptor.Signature);
		}
		if (flag2)
		{
			throw new InvalidOperationException(descriptor.Name + " hook target already appears patched by another tool.");
		}
		throw new InvalidOperationException(descriptor.Name + " hook target bytes did not match the expected FH5/FH6 sequence. Found: " + text);
	}

	private static ProfileIntegerHookLayout GetProfileIntegerFieldsLayout()
	{
		return ProfileIntegerFieldsLayout;
	}

	private static ProfileIntegerHookLayout BuildProfileIntegerFieldsLayout()
	{
		List<byte> code = new List<byte>();
		Dictionary<string, int> labels = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		Action<string> action = delegate(string label)
		{
			labels[label] = code.Count;
		};
		code.AddRange(new byte[4] { 72, 139, 79, 8 });
		code.AddRange(new byte[1] { 80 });
		code.AddRange(new byte[5] { 72, 139, 84, 36, 40 });
		EmitMovRaxAscii8(code, "Credits");
		code.AddRange(new byte[4] { 72, 57, 66, 180 });
		EmitJne(code, fixups, "checkXpShort");
		code.AddRange(new byte[2] { 139, 7 });
		EmitRipStoreEax(code, fixups2, "creditsCapture");
		EmitRipCmpByteImm(code, fixups2, "creditsToggle", 1);
		EmitJne(code, fixups, "done");
		EmitRipLoadEdx(code, fixups2, "creditsValue");
		code.AddRange(new byte[2] { 137, 23 });
		EmitJmp(code, fixups, "done");
		action("checkXpShort");
		EmitMovRaxAscii8(code, "TotalXP");
		EmitCmpRdxOffsetRax(code, 180);
		EmitJne(code, fixups, "checkXpMain");
		EmitJmp(code, fixups, "xpTotalMatch");
		action("checkXpMain");
		EmitMovRaxAscii8(code, "Main/Tot");
		EmitCmpRdxOffsetRax(code, 180);
		EmitJne(code, fixups, "checkWristbandLevel");
		code.AddRange(new byte[7] { 129, 122, 188, 97, 108, 88, 80 });
		EmitJne(code, fixups, "checkWristbandLevel");
		EmitJmp(code, fixups, "xpTotalMatch");
		action("checkWristbandLevel");
		EmitMovRaxAscii8(code, "Wristban");
		EmitCmpRdxOffsetRax(code, 180);
		EmitJne(code, fixups, "checkTotalSkills");
		code.AddRange(new byte[7] { 129, 122, 188, 100, 76, 101, 118 });
		EmitJne(code, fixups, "checkTotalSkills");
		code.AddRange(new byte[6] { 102, 129, 122, 192, 101, 108 });
		EmitJne(code, fixups, "checkTotalSkills");
		code.AddRange(new byte[4] { 128, 122, 194, 0 });
		EmitJne(code, fixups, "checkTotalSkills");
		EmitJmp(code, fixups, "xpTotalMatch");
		action("checkTotalSkills");
		EmitMovRaxAscii8(code, "TotalSki");
		EmitCmpRdxOffsetRax(code, 180);
		EmitJne(code, fixups, "checkXpExact");
		code.AddRange(new byte[7] { 129, 122, 188, 108, 108, 115, 0 });
		EmitJne(code, fixups, "checkXpExact");
		EmitJmp(code, fixups, "xpTotalMatch");
		action("checkXpExact");
		code.AddRange(new byte[6] { 102, 129, 122, 180, 88, 80 });
		EmitJne(code, fixups, "checkLevelExact");
		code.AddRange(new byte[4] { 128, 122, 182, 0 });
		EmitJne(code, fixups, "checkLevelExact");
		EmitJmp(code, fixups, "xpTotalMatch");
		action("checkLevelExact");
		code.AddRange(new byte[7] { 129, 122, 180, 76, 101, 118, 101 });
		EmitJne(code, fixups, "done");
		code.AddRange(new byte[4] { 128, 122, 184, 108 });
		EmitJne(code, fixups, "done");
		code.AddRange(new byte[4] { 128, 122, 185, 0 });
		EmitJne(code, fixups, "done");
		EmitJmp(code, fixups, "xpTotalMatch");
		action("xpTotalMatch");
		code.AddRange(new byte[2] { 139, 7 });
		EmitRipStoreEax(code, fixups2, "xpCapture");
		EmitRipCmpByteImm(code, fixups2, "xpToggle", 1);
		EmitJne(code, fixups, "done");
		EmitRipLoadEdx(code, fixups2, "xpValue");
		code.AddRange(new byte[2] { 137, 23 });
		EmitJmp(code, fixups, "done");
		action("done");
		code.AddRange(new byte[1] { 88 });
		code.AddRange(new byte[2] { 49, 210 });
		int num = Align4(code.Count + 5);
		int num2 = num++;
		int num3 = num;
		num += 4;
		int num4 = num;
		num += 4;
		int num5 = num++;
		int num6 = num;
		num += 4;
		int num7 = num;
		num += 4;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("creditsToggle", num2);
		dictionary.Add("creditsValue", num3);
		dictionary.Add("creditsCapture", num4);
		dictionary.Add("xpToggle", num5);
		dictionary.Add("xpValue", num6);
		dictionary.Add("xpCapture", num7);
		Dictionary<string, int> labels2 = dictionary;
		PatchRelativeFixups(code, fixups, labels);
		PatchRelativeFixups(code, fixups2, labels2);
		ProfileIntegerHookLayout profileIntegerHookLayout = new ProfileIntegerHookLayout();
		profileIntegerHookLayout.Asm = code.ToArray();
		profileIntegerHookLayout.CreditsToggleOffset = num2;
		profileIntegerHookLayout.CreditsValueOffset = num3;
		profileIntegerHookLayout.CreditsCaptureOffset = num4;
		profileIntegerHookLayout.XpToggleOffset = num5;
		profileIntegerHookLayout.XpValueOffset = num6;
		profileIntegerHookLayout.XpCaptureOffset = num7;
		profileIntegerHookLayout.MinimumSize = num;
		return profileIntegerHookLayout;
	}

	private static void EmitMovRaxAscii8(List<byte> code, string text)
	{
		byte[] array = new byte[8];
		byte[] bytes = Encoding.ASCII.GetBytes(text);
		Buffer.BlockCopy(bytes, 0, array, 0, Math.Min(bytes.Length, array.Length));
		code.Add(72);
		code.Add(184);
		code.AddRange(array);
	}

	private static void EmitCmpRdxOffsetRax(List<byte> code, byte offset)
	{
		code.AddRange(new byte[4] { 72, 57, 66, offset });
	}

	private static void EmitCmpRcxDwordOffsetImm(List<byte> code, byte offset, uint value)
	{
		code.AddRange(new byte[3] { 129, 121, offset });
		code.AddRange(BitConverter.GetBytes(value));
	}

	private static void EmitJne(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(15);
		code.Add(133);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitJe(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(15);
		code.Add(132);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitJae(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(15);
		code.Add(131);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitJle(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(15);
		code.Add(142);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitJa(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(15);
		code.Add(135);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitJmp(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(233);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreEax(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(137);
		code.Add(5);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreEdx(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(137);
		code.Add(21);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreEbx(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(137);
		code.Add(29);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreRdi(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(72);
		code.Add(137);
		code.Add(61);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreRbx(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(72);
		code.Add(137);
		code.Add(29);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreR15(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(76);
		code.Add(137);
		code.Add(61);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreRcx(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(72);
		code.Add(137);
		code.Add(13);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreRdx(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(72);
		code.Add(137);
		code.Add(21);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipLoadEdx(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(139);
		code.Add(21);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipLoadEax(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(139);
		code.Add(5);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipLoadEbx(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.Add(139);
		code.Add(29);
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreXmm1(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 17, 13 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreXmm6(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 17, 53 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreXmm7(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 17, 61 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreXmm0(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 17, 5 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreXmmByRegister(List<byte> code, List<ProfileAsmFixup> fixups, int xmmRegister, string label)
	{
		switch (xmmRegister)
		{
		default:
			throw new InvalidOperationException("Unsupported XMM register for scalar capture.");
		case 6:
			EmitRipStoreXmm6(code, fixups, label);
			break;
		case 7:
			EmitRipStoreXmm7(code, fixups, label);
			break;
		case 0:
			EmitRipStoreXmm0(code, fixups, label);
			break;
		case 1:
			EmitRipStoreXmm1(code, fixups, label);
			break;
		}
	}

	private static void EmitRipStoreXmm1Vector(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[3] { 15, 17, 13 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreXmm2Vector(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[3] { 15, 17, 21 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipStoreXmm0Vector(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[3] { 15, 17, 5 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipMulXmm1(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 89, 13 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipMulXmm2(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 89, 21 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipMulXmm6(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 89, 53 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipMulXmm7(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 89, 61 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipMulXmmByRegister(List<byte> code, List<ProfileAsmFixup> fixups, int xmmRegister, string label)
	{
		switch (xmmRegister)
		{
		default:
			throw new InvalidOperationException("Unsupported XMM register for scalar multiply.");
		case 6:
			EmitRipMulXmm6(code, fixups, label);
			break;
		case 7:
			EmitRipMulXmm7(code, fixups, label);
			break;
		case 0:
			EmitRipMulXmm0(code, fixups, label);
			break;
		case 1:
			EmitRipMulXmm1(code, fixups, label);
			break;
		}
	}

	private static void EmitMovapsXmm1FromRegister(List<byte> code, int sourceRegister)
	{
		switch (sourceRegister)
		{
		default:
			throw new InvalidOperationException("Unsupported XMM source register.");
		case 6:
			code.AddRange(new byte[3] { 15, 40, 206 });
			break;
		case 7:
			code.AddRange(new byte[3] { 15, 40, 207 });
			break;
		case 0:
			code.AddRange(new byte[3] { 15, 40, 200 });
			break;
		case 1:
			break;
		}
	}

	private static void EmitRipLoadXmm0(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 16, 5 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipLoadXmm1(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 16, 13 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipLoadXmm6(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 16, 53 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipLoadXmm7(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 16, 61 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipLoadXmm0Vector(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[3] { 15, 16, 5 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipMulXmm0(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 89, 5 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitOneMinusRipValueIntoXmm1(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[1] { 80 });
		code.AddRange(new byte[5] { 184, 0, 0, 128, 63 });
		code.AddRange(new byte[4] { 102, 15, 110, 200 });
		code.AddRange(new byte[1] { 88 });
		EmitRipSubXmm1(code, fixups, label);
	}

	private static void EmitRipAddXmm1(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 88, 13 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipAddXmm0(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 88, 5 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipSubXmm1(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 92, 13 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipSubXmm0(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		code.AddRange(new byte[4] { 243, 15, 92, 5 });
		AddRelativeFixup(code, fixups, label);
	}

	private static void EmitRipCmpByteImm(List<byte> code, List<ProfileAsmFixup> fixups, string label, byte value)
	{
		code.Add(128);
		code.Add(61);
		int offset = ReserveRelativeFixup(code);
		code.Add(value);
		fixups.Add(new ProfileAsmFixup
		{
			Offset = offset,
			InstructionEnd = code.Count,
			Label = label
		});
	}

	private static void EmitRipStoreByteImm(List<byte> code, List<ProfileAsmFixup> fixups, string label, byte value)
	{
		code.Add(198);
		code.Add(5);
		int offset = ReserveRelativeFixup(code);
		code.Add(value);
		fixups.Add(new ProfileAsmFixup
		{
			Offset = offset,
			InstructionEnd = code.Count,
			Label = label
		});
	}

	private static void AddRelativeFixup(List<byte> code, List<ProfileAsmFixup> fixups, string label)
	{
		int offset = ReserveRelativeFixup(code);
		fixups.Add(new ProfileAsmFixup
		{
			Offset = offset,
			InstructionEnd = code.Count,
			Label = label
		});
	}

	private static int ReserveRelativeFixup(List<byte> code)
	{
		int count = code.Count;
		code.Add(0);
		code.Add(0);
		code.Add(0);
		code.Add(0);
		return count;
	}

	private static void PatchRelativeFixups(List<byte> code, IEnumerable<ProfileAsmFixup> fixups, Dictionary<string, int> labels)
	{
		foreach (ProfileAsmFixup fixup in fixups)
		{
			if (labels.TryGetValue(fixup.Label, out var value))
			{
				int value2 = value - fixup.InstructionEnd;
				byte[] bytes = BitConverter.GetBytes(value2);
				for (int i = 0; i < 4; i++)
				{
					code[fixup.Offset + i] = bytes[i];
				}
				continue;
			}
			throw new InvalidOperationException("Missing profile hook label: " + fixup.Label);
		}
	}

	private static int Align4(int value)
	{
		return (value + 3) & -4;
	}

	private static int Align8(int value)
	{
		return (value + 7) & -8;
	}

	private static RuntimeProfileHookDescriptor GetProfileHookDescriptor(RuntimeProfileFeature feature)
	{
		ProfileIntegerHookLayout profileIntegerFieldsLayout = ProfileIntegerFieldsLayout;
		switch (feature)
		{
		default:
			throw new InvalidOperationException("Unsupported runtime profile feature.");
		case RuntimeProfileFeature.Credits:
		{
			RuntimeProfileHookDescriptor runtimeProfileHookDescriptor5 = new RuntimeProfileHookDescriptor();
			runtimeProfileHookDescriptor5.Key = "ProfileIntFields";
			runtimeProfileHookDescriptor5.Name = "Credits";
			runtimeProfileHookDescriptor5.Signature = "E8 ? ? ? ? 89 84 ? ? ? ? ? 4C 8D ? ? ? ? ? 48 8B";
			runtimeProfileHookDescriptor5.ResolveCallTarget = true;
			runtimeProfileHookDescriptor5.CallTargetOffset = 24;
			runtimeProfileHookDescriptor5.HookSize = 6;
			runtimeProfileHookDescriptor5.ExpectedOriginal = new byte[6] { 72, 139, 79, 8, 51, 210 };
			runtimeProfileHookDescriptor5.ToggleOffset = profileIntegerFieldsLayout.CreditsToggleOffset;
			runtimeProfileHookDescriptor5.ValueOffset = profileIntegerFieldsLayout.CreditsValueOffset;
			runtimeProfileHookDescriptor5.CaptureOffset = profileIntegerFieldsLayout.CreditsCaptureOffset;
			runtimeProfileHookDescriptor5.MinimumSize = profileIntegerFieldsLayout.MinimumSize;
			runtimeProfileHookDescriptor5.Asm = profileIntegerFieldsLayout.Asm;
			return runtimeProfileHookDescriptor5;
		}
		case RuntimeProfileFeature.Wheelspins:
		{
			RuntimeProfileHookDescriptor runtimeProfileHookDescriptor4 = new RuntimeProfileHookDescriptor();
			runtimeProfileHookDescriptor4.Key = "Wheelspins";
			runtimeProfileHookDescriptor4.Name = "Wheelspins";
			runtimeProfileHookDescriptor4.Signature = "48 89 5C 24 08 57 48 83 EC 20 48 8B FA 33 D2 48 8B 4F 10";
			runtimeProfileHookDescriptor4.MatchOffset = 28;
			runtimeProfileHookDescriptor4.HookSize = 5;
			runtimeProfileHookDescriptor4.ExpectedOriginal = new byte[5] { 51, 210, 139, 95, 8 };
			runtimeProfileHookDescriptor4.ToggleOffset = 39;
			runtimeProfileHookDescriptor4.ValueOffset = 40;
			runtimeProfileHookDescriptor4.CaptureOffset = 44;
			runtimeProfileHookDescriptor4.Asm = new byte[34]
			{
				80, 139, 71, 8, 137, 5, 34, 0, 0, 0,
				88, 128, 61, 21, 0, 0, 0, 1, 117, 9,
				139, 21, 14, 0, 0, 0, 137, 87, 8, 51,
				210, 139, 95, 8
			};
			return runtimeProfileHookDescriptor4;
		}
		case RuntimeProfileFeature.SkillPoints:
		{
			RuntimeProfileHookDescriptor runtimeProfileHookDescriptor3 = new RuntimeProfileHookDescriptor();
			runtimeProfileHookDescriptor3.Key = "SkillPoints";
			runtimeProfileHookDescriptor3.Name = "Skill Points";
			runtimeProfileHookDescriptor3.Signature = "85 D2 78 32 48 89 5C 24 08 57 48 83 EC 20 8B DA 48 8B F9 48 8B 49 48";
			runtimeProfileHookDescriptor3.MatchOffset = 34;
			runtimeProfileHookDescriptor3.HookSize = 5;
			runtimeProfileHookDescriptor3.ExpectedOriginal = new byte[5] { 51, 210, 137, 95, 64 };
			runtimeProfileHookDescriptor3.ToggleOffset = 36;
			runtimeProfileHookDescriptor3.ValueOffset = 37;
			runtimeProfileHookDescriptor3.CaptureOffset = 41;
			runtimeProfileHookDescriptor3.Asm = new byte[31]
			{
				80, 139, 71, 64, 137, 5, 31, 0, 0, 0,
				88, 128, 61, 18, 0, 0, 0, 1, 117, 6,
				139, 29, 11, 0, 0, 0, 51, 210, 137, 95,
				64
			};
			return runtimeProfileHookDescriptor3;
		}
		case RuntimeProfileFeature.DriftScoreMultiplier:
		{
			RuntimeProfileHookDescriptor runtimeProfileHookDescriptor2 = new RuntimeProfileHookDescriptor();
			runtimeProfileHookDescriptor2.Key = "DriftScoreMultiplier";
			runtimeProfileHookDescriptor2.Name = "Drift Score Multiplier";
			runtimeProfileHookDescriptor2.Signature = "E8 ? ? ? ? F3 0F ? ? 0F 28 ? ? ? 0F 28";
			runtimeProfileHookDescriptor2.MatchOffset = 5;
			runtimeProfileHookDescriptor2.HookSize = 9;
			runtimeProfileHookDescriptor2.ExpectedOriginal = new byte[9] { 243, 15, 88, 247, 15, 40, 124, 36, 32 };
			runtimeProfileHookDescriptor2.ToggleOffset = 31;
			runtimeProfileHookDescriptor2.ValueOffset = 32;
			runtimeProfileHookDescriptor2.Asm = new byte[26]
			{
				128, 61, 24, 0, 0, 0, 1, 117, 8, 243,
				15, 89, 61, 15, 0, 0, 0, 243, 15, 88,
				247, 15, 40, 124, 36, 32
			};
			return runtimeProfileHookDescriptor2;
		}
		case RuntimeProfileFeature.SpeedZoneSpeed:
			return GetPrSpeedComputationDescriptor("Speed Zone Multiplier");
		case RuntimeProfileFeature.DangerSignDistance:
			return GetDangerSignDistanceDescriptor();
		case RuntimeProfileFeature.SpeedTrapMultiplier:
			return GetSpeedTrapMultiplierDescriptor();
		case RuntimeProfileFeature.Gravity:
			return GetGravityDescriptor();
		case RuntimeProfileFeature.FreeClothing:
			return GetFreeClothingDescriptor();
		case RuntimeProfileFeature.Acceleration:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.Acceleration);
		case RuntimeProfileFeature.SuperBrake:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.SuperBrake);
		case RuntimeProfileFeature.AdaptiveBrake:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.AdaptiveBrake);
		case RuntimeProfileFeature.Jump:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.Jump);
		case RuntimeProfileFeature.Boost:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.Boost);
		case RuntimeProfileFeature.DriftMode:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.DriftMode);
		case RuntimeProfileFeature.NoWaterDrag:
			return GetNoWaterDragDescriptor();
		case RuntimeProfileFeature.SuperHandling:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.SuperHandling);
		case RuntimeProfileFeature.LandingStabilizer:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.LandingStabilizer);
		case RuntimeProfileFeature.SlideCalmer:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.SlideCalmer);
		case RuntimeProfileFeature.RoadMagnet:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.RoadMagnet);
		case RuntimeProfileFeature.SpeedTamer:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.SpeedTamer);
		case RuntimeProfileFeature.AirLift:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.AirLift);
		case RuntimeProfileFeature.BounceCushion:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.BounceCushion);
		case RuntimeProfileFeature.MomentumControl:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.MomentumControl);
		case RuntimeProfileFeature.LeftRightCalm:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.LeftRightCalm);
		case RuntimeProfileFeature.ForwardBackCalm:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.ForwardBackCalm);
		case RuntimeProfileFeature.SidePush:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.SidePush);
		case RuntimeProfileFeature.ForwardPush:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.ForwardPush);
		case RuntimeProfileFeature.VerticalTrim:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.VerticalTrim);
		case RuntimeProfileFeature.SideLock:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.SideLock);
		case RuntimeProfileFeature.ForwardLock:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.ForwardLock);
		case RuntimeProfileFeature.VerticalHold:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.VerticalHold);
		case RuntimeProfileFeature.MotionFreeze:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.MotionFreeze);
		case RuntimeProfileFeature.WheelieBoost:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.WheelieBoost);
		case RuntimeProfileFeature.DriftKick:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.DriftKick);
		case RuntimeProfileFeature.HoverGlide:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.HoverGlide);
		case RuntimeProfileFeature.AirBrake:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.AirBrake);
		case RuntimeProfileFeature.CornerStabilizer:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.CornerStabilizer);
		case RuntimeProfileFeature.PlantedBoost:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.PlantedBoost);
		case RuntimeProfileFeature.ForwardLaunch:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.ForwardLaunch);
		case RuntimeProfileFeature.StraightLaunch:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.StraightLaunch);
		case RuntimeProfileFeature.DragLaunchAssist:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.DragLaunchAssist);
		case RuntimeProfileFeature.TireBite:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.TireBite);
		case RuntimeProfileFeature.GripLock:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.GripLock);
		case RuntimeProfileFeature.ForwardGrip:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.ForwardGrip);
		case RuntimeProfileFeature.RailGrip:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.RailGrip);
		case RuntimeProfileFeature.HighSpeedStabilizer:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.HighSpeedStabilizer);
		case RuntimeProfileFeature.GroundClamp:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.GroundClamp);
		case RuntimeProfileFeature.StabilityRail:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.StabilityRail);
		case RuntimeProfileFeature.AirControl:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.AirControl);
		case RuntimeProfileFeature.CornerBite:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.CornerBite);
		case RuntimeProfileFeature.SpinRecovery:
			return GetVehicleControlDescriptor(RuntimeProfileFeature.SpinRecovery);
		case RuntimeProfileFeature.TeleportToWaypoint:
			return GetWaypointDestinationCaptureDescriptor(0);
		case RuntimeProfileFeature.MissionTimerScale:
			return GetMissionTimerScaleDescriptor();
		case RuntimeProfileFeature.RaceTimerScale:
			return GetRaceTimerScaleDescriptor();
		case RuntimeProfileFeature.TimeOfDay:
			return GetTimeOfDayDescriptor();
		case RuntimeProfileFeature.FovSlider:
			return GetFovSliderDescriptor();
		case RuntimeProfileFeature.NoBuildLimit:
			return GetNoBuildLimitDescriptor();
		case RuntimeProfileFeature.FreezeAI:
			return GetFreezeAIDescriptor();
		case RuntimeProfileFeature.NoClip:
			return GetNoClipDescriptor();
		case RuntimeProfileFeature.SeriesPoints:
			return GetSeriesPointsDescriptor();
		case RuntimeProfileFeature.NoSkillBreak:
		{
			RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
			runtimeProfileHookDescriptor.Key = "NoSkillBreak";
			runtimeProfileHookDescriptor.Name = "No Skill Break";
			runtimeProfileHookDescriptor.Signature = "0F B6 ? 40 38 ? ? ? ? ? 74 ? 84 C0";
			runtimeProfileHookDescriptor.MatchOffset = 0;
			runtimeProfileHookDescriptor.HookSize = 10;
			runtimeProfileHookDescriptor.ExpectedOriginal = new byte[10] { 15, 182, 240, 64, 56, 171, 116, 2, 0, 0 };
			runtimeProfileHookDescriptor.ToggleOffset = 26;
			runtimeProfileHookDescriptor.ValueOffset = -1;
			runtimeProfileHookDescriptor.Asm = new byte[21]
			{
				128, 61, 19, 0, 0, 0, 1, 117, 2, 48,
				192, 15, 182, 240, 64, 56, 171, 116, 2, 0,
				0
			};
			return runtimeProfileHookDescriptor;
		}
		}
	}

	private static RuntimeProfileHookDescriptor[] GetProfileHookDescriptors(RuntimeProfileFeature feature)
	{
		return feature switch
		{
			RuntimeProfileFeature.SeriesPoints => new RuntimeProfileHookDescriptor[2]
			{
				GetSeriesPointsDescriptor(),
				GetSeriesPointsDisplayDescriptor()
			}, 
			RuntimeProfileFeature.TimeOfDay => new RuntimeProfileHookDescriptor[3]
			{
				GetTimeOfDayDescriptor(),
				GetTimeOfDaySetterDescriptor(),
				GetTimeOfDayGetterDescriptor()
			}, 
			RuntimeProfileFeature.DangerSignDistance => new RuntimeProfileHookDescriptor[1] { GetDangerSignDistanceDescriptor() }, 
			RuntimeProfileFeature.SpeedTrapMultiplier => new RuntimeProfileHookDescriptor[1] { GetSpeedTrapMultiplierDescriptor() }, 
			_ => new RuntimeProfileHookDescriptor[1] { GetProfileHookDescriptor(feature) }, 
		};
	}

	private static RuntimeProfileHookDescriptor GetPrSpeedComputationDescriptor(string name)
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildSpeedZoneSpeedAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "PrSpeedComputation";
		runtimeProfileHookDescriptor.Name = name;
		runtimeProfileHookDescriptor.Signature = "F3 0F 5E B5 88 00 00 00 0F 28 C6 0F 28 74 24 20";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 11;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[11]
		{
			243, 15, 94, 181, 136, 0, 0, 0, 15, 40,
			198
		};
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildSpeedZoneSpeedAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		list.AddRange(new byte[8] { 243, 15, 94, 181, 136, 0, 0, 0 });
		EmitRipStoreXmm6(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		EmitRipMulXmm6(list, fixups2, "value");
		dictionary["done"] = list.Count;
		list.AddRange(new byte[3] { 15, 40, 198 });
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetSpeedTrapMultiplierDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildSpeedTrapSpeedAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "SpeedTrapMultiplier";
		runtimeProfileHookDescriptor.Name = "Speed Trap Multiplier";
		runtimeProfileHookDescriptor.Signature = "48 8B 95 90 01 00 00 48 85 D2 74 ? 8B 42 08 85 C0 74 ? 8D 48 01 F0 0F B1 4A 08 74 ? 85 C0 75 ? 48 8B 5C 24 28 48 8B 4C 24 20 E8 ? ? ? ? 0F 28 F0 48 85 DB";
		runtimeProfileHookDescriptor.MatchOffset = 48;
		runtimeProfileHookDescriptor.HookSize = 6;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[6] { 15, 40, 240, 72, 133, 219 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetSpeedTrapDisplayDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildSpeedTrapDisplayAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "SpeedTrapDisplayMultiplier";
		runtimeProfileHookDescriptor.Name = "Speed Trap Multiplier";
		runtimeProfileHookDescriptor.Signature = "48 8B CE E8 ? ? ? ? 0F 28 CE 48 8B C8 E8 ? ? ? ? 4C 8D 9C 24 90 00 00 00";
		runtimeProfileHookDescriptor.MatchOffset = 8;
		runtimeProfileHookDescriptor.HookSize = 6;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[6] { 15, 40, 206, 72, 139, 200 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildSpeedTrapDisplayAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		list.AddRange(new byte[3] { 15, 40, 206 });
		list.AddRange(new byte[4] { 242, 15, 90, 193 });
		EmitRipStoreXmm0(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		list.AddRange(new byte[4] { 243, 15, 90, 5 });
		AddRelativeFixup(list, fixups2, "value");
		list.AddRange(new byte[4] { 242, 15, 89, 200 });
		dictionary["done"] = list.Count;
		list.AddRange(new byte[3] { 72, 139, 200 });
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static byte[] BuildSpeedTrapSpeedAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		list.AddRange(new byte[3] { 15, 40, 240 });
		list.AddRange(new byte[4] { 242, 15, 90, 198 });
		EmitRipStoreXmm0(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		list.AddRange(new byte[4] { 243, 15, 90, 5 });
		AddRelativeFixup(list, fixups2, "value");
		list.AddRange(new byte[4] { 242, 15, 89, 240 });
		dictionary["done"] = list.Count;
		list.AddRange(new byte[3] { 15, 40, 198 });
		list.AddRange(new byte[3] { 72, 133, 219 });
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetSpeedTrapVectorResultDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildSpeedTrapVectorResultAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "SpeedTrapVectorResult";
		runtimeProfileHookDescriptor.Name = "Speed Trap Multiplier";
		runtimeProfileHookDescriptor.Signature = "48 8D 4E 20 66 0F 6F C6 66 0F 73 D8 04 66 0F 7E 41 18 E8 ? ? ? ? 48 8D 4E 40";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 8;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[8] { 72, 141, 78, 32, 102, 15, 111, 198 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildSpeedTrapVectorResultAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipStoreXmm6(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		list.AddRange(new byte[4] { 72, 131, 236, 16 });
		list.AddRange(new byte[5] { 243, 15, 127, 4, 36 });
		EmitRipLoadXmm0(list, fixups2, "value");
		list.AddRange(new byte[4] { 15, 198, 192, 0 });
		list.AddRange(new byte[3] { 15, 89, 240 });
		list.AddRange(new byte[5] { 243, 15, 111, 4, 36 });
		list.AddRange(new byte[4] { 72, 131, 196, 16 });
		dictionary["original"] = list.Count;
		list.AddRange(new byte[4] { 72, 141, 78, 32 });
		list.AddRange(new byte[4] { 102, 15, 111, 198 });
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetSpeedTrapFinalStoreDescriptorA()
	{
		return GetScalarXmmMultiplierDescriptor("SpeedTrapFinalStoreA", "Speed Trap Multiplier", "F3 0F 11 7D 20 48 85 FF 74 29 8B C6 F0 0F C1 47 08", 0, 5, 7, new byte[5] { 243, 15, 17, 125, 32 });
	}

	private static RuntimeProfileHookDescriptor GetSpeedTrapFinalStoreDescriptorB()
	{
		return GetScalarXmmMultiplierDescriptor("SpeedTrapFinalStoreB", "Speed Trap Multiplier", "F3 0F 11 7C 24 20 45 33 C0 BA 04 00 00 00 48 8D 4C 24 20", 0, 6, 7, new byte[6] { 243, 15, 17, 124, 36, 32 });
	}

	private static RuntimeProfileHookDescriptor GetSpeedTrapFinalStoreDescriptorC()
	{
		return GetScalarXmmMultiplierDescriptor("SpeedTrapFinalStoreC", "Speed Trap Multiplier", "F3 0F 11 73 78 33 D2 48 8B 8B 80 00 00 00 E8 ? ? ? ? 90", 0, 5, 6, new byte[5] { 243, 15, 17, 115, 120 });
	}

	private static RuntimeProfileHookDescriptor GetSpeedTrapPublisherDescriptorA()
	{
		return GetPublisherMultiplierDescriptor("SpeedTrapPublisherA", "Speed Trap Multiplier", "0F 28 CF 48 8B 4C 24 20 E8 ? ? ? ? 90 48 85 FF", 0, 8, 7, new byte[8] { 15, 40, 207, 72, 139, 76, 36, 32 }, new byte[5] { 72, 139, 76, 36, 32 });
	}

	private static RuntimeProfileHookDescriptor GetSpeedTrapPublisherDescriptorB()
	{
		return GetPublisherMultiplierDescriptor("SpeedTrapPublisherB", "Speed Trap Multiplier", "48 8B 01 0F 28 CF FF 90 D0 00 00 00 48 8B CB E8 ? ? ? ?", 3, 9, 7, new byte[9] { 15, 40, 207, 255, 144, 208, 0, 0, 0 }, new byte[6] { 255, 144, 208, 0, 0, 0 });
	}

	private static RuntimeProfileHookDescriptor GetSpeedTrapPublisherDescriptorC()
	{
		return GetPublisherMultiplierDescriptor("SpeedTrapPublisherC", "Speed Trap Multiplier", "48 8B CE E8 ? ? ? ? 0F 28 CE 48 8B C8 E8 ? ? ? ? 4C 8D 9C 24 90 00 00 00", 8, 6, 6, new byte[6] { 15, 40, 206, 72, 139, 200 }, new byte[3] { 72, 139, 200 });
	}

	private static RuntimeProfileHookDescriptor GetDangerSignAccumulatorDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildDangerSignAccumulatorAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "DangerSignAccumulator";
		runtimeProfileHookDescriptor.Name = "Danger Sign Multiplier";
		runtimeProfileHookDescriptor.Signature = "0F 28 F9 E8 ? ? ? ? 48 8B 4B 08 33 D2 F3 0F 10 33 E8 ? ? ? ? F3 0F 58 F7 0F 28 7C 24 20 0F 28 C6";
		runtimeProfileHookDescriptor.MatchOffset = 23;
		runtimeProfileHookDescriptor.HookSize = 9;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[9] { 243, 15, 88, 247, 15, 40, 124, 36, 32 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildDangerSignAccumulatorAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipStoreXmm7(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		EmitRipMulXmm7(list, fixups2, "value");
		dictionary["done"] = list.Count;
		list.AddRange(new byte[4] { 243, 15, 88, 247 });
		list.AddRange(new byte[5] { 15, 40, 124, 36, 32 });
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetDangerSignDistanceDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildDangerSignDistanceAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "DangerSignDistance";
		runtimeProfileHookDescriptor.Name = "Danger Sign Multiplier";
		runtimeProfileHookDescriptor.Signature = "F3 41 0F 59 C2 0F 28 C8 48 8D 4B 28 E8 ? ? ? ? F3 0F 11 45 97 45 33 C0 BA 04 00 00 00";
		runtimeProfileHookDescriptor.MatchOffset = 5;
		runtimeProfileHookDescriptor.HookSize = 7;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[7] { 15, 40, 200, 72, 141, 75, 40 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetDangerSignDisplayDescriptorA()
	{
		return GetDangerSignDisplayDescriptor("DangerSignDisplayMultiplierA", "48 8B CB E8 ? ? ? ? 0F 28 C8 48 8B 4D 97 E8 ? ? ? ? 90 48 85 FF", new byte[4] { 72, 139, 77, 151 });
	}

	private static RuntimeProfileHookDescriptor GetDangerSignDisplayDescriptorB()
	{
		return GetDangerSignDisplayDescriptor("DangerSignDisplayMultiplierB", "48 8B CE E8 ? ? ? ? 0F 28 C8 48 8B 4D 97 E8 ? ? ? ? 90 48 85 DB", new byte[4] { 72, 139, 77, 151 });
	}

	private static RuntimeProfileHookDescriptor GetDangerSignDisplayDescriptorC()
	{
		return GetDangerSignDisplayDescriptor("DangerSignDisplayMultiplierC", "48 8D 4F 28 E8 ? ? ? ? 0F 28 C8 48 8B 4D CF E8 ? ? ? ? 90 48 85 DB", new byte[4] { 72, 139, 77, 207 });
	}

	private static RuntimeProfileHookDescriptor GetDangerSignDisplayDescriptorD()
	{
		return GetPublisherMultiplierDescriptor("DangerSignDisplayMultiplierD", "Danger Sign Multiplier", "F3 0F 10 77 28 33 D2 48 8B 4F 30 E8 ? ? ? ? 0F 28 CE 48 8B 4C 24 20 E8 ? ? ? ?", 16, 8, 6, new byte[8] { 15, 40, 206, 72, 139, 76, 36, 32 }, new byte[5] { 72, 139, 76, 36, 32 });
	}

	private static RuntimeProfileHookDescriptor GetDangerSignPropertyStoreDescriptorA()
	{
		return GetScalarXmmMultiplierDescriptor("DangerSignPropertyStoreA", "Danger Sign Multiplier", "F3 0F 11 73 28 33 D2 48 8B 4B 30 E8 ? ? ? ? 90 48 8B 4D 9F", 0, 5, 6, new byte[5] { 243, 15, 17, 115, 40 });
	}

	private static RuntimeProfileHookDescriptor GetDangerSignPropertyStoreDescriptorB()
	{
		return GetScalarXmmMultiplierDescriptor("DangerSignPropertyStoreB", "Danger Sign Multiplier", "F3 0F 11 77 28 33 D2 48 8B 4F 30 E8 ? ? ? ? 90 48 8B 4D D7", 0, 5, 6, new byte[5] { 243, 15, 17, 119, 40 });
	}

	private static RuntimeProfileHookDescriptor GetDangerSignObjectStoreDescriptorA()
	{
		return GetScalarXmmMultiplierDescriptor("DangerSignObjectStoreA", "Danger Sign Multiplier", "48 8B 44 24 20 F3 0F 11 70 20 BE FF FF FF FF 48 85 DB", 5, 5, 6, new byte[5] { 243, 15, 17, 112, 32 });
	}

	private static RuntimeProfileHookDescriptor GetDangerSignObjectStoreDescriptorB()
	{
		return GetScalarXmmMultiplierDescriptor("DangerSignObjectStoreB", "Danger Sign Multiplier", "48 8B 45 CF F3 0F 11 70 20 BE FF FF FF FF 48 85 DB", 4, 5, 6, new byte[5] { 243, 15, 17, 112, 32 });
	}

	private static RuntimeProfileHookDescriptor GetDangerSignDisplayDescriptor(string key, string signature, byte[] originalTail)
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildDangerSignDisplayAsm(originalTail, out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = key;
		runtimeProfileHookDescriptor.Name = "Danger Sign Multiplier";
		runtimeProfileHookDescriptor.Signature = signature;
		runtimeProfileHookDescriptor.MatchOffset = 8;
		runtimeProfileHookDescriptor.HookSize = 7;
		byte[] array = new byte[7] { 15, 40, 200, 0, 0, 0, 0 };
		array[3] = originalTail[0];
		array[4] = originalTail[1];
		array[5] = originalTail[2];
		array[6] = originalTail[3];
		runtimeProfileHookDescriptor.ExpectedOriginal = array;
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetScalarXmmMultiplierDescriptor(string key, string name, string signature, int matchOffset, int hookSize, int xmmRegister, byte[] originalBytes)
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildScalarXmmMultiplierAsm(xmmRegister, originalBytes, out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = key;
		runtimeProfileHookDescriptor.Name = name;
		runtimeProfileHookDescriptor.Signature = signature;
		runtimeProfileHookDescriptor.MatchOffset = matchOffset;
		runtimeProfileHookDescriptor.HookSize = hookSize;
		runtimeProfileHookDescriptor.ExpectedOriginal = originalBytes;
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetPublisherMultiplierDescriptor(string key, string name, string signature, int matchOffset, int hookSize, int sourceRegister, byte[] expectedOriginal, byte[] originalTail)
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildPublisherMultiplierAsm(sourceRegister, originalTail, out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = key;
		runtimeProfileHookDescriptor.Name = name;
		runtimeProfileHookDescriptor.Signature = signature;
		runtimeProfileHookDescriptor.MatchOffset = matchOffset;
		runtimeProfileHookDescriptor.HookSize = hookSize;
		runtimeProfileHookDescriptor.ExpectedOriginal = expectedOriginal;
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildScalarXmmMultiplierAsm(int xmmRegister, byte[] originalBytes, out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipStoreXmmByRegister(list, fixups2, xmmRegister, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		EmitRipMulXmmByRegister(list, fixups2, xmmRegister, "value");
		dictionary["done"] = list.Count;
		list.AddRange(originalBytes);
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static byte[] BuildPublisherMultiplierAsm(int sourceRegister, byte[] originalTail, out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitMovapsXmm1FromRegister(list, sourceRegister);
		EmitRipStoreXmm1(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		EmitRipMulXmm1(list, fixups2, "value");
		dictionary["done"] = list.Count;
		list.AddRange(originalTail);
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static byte[] BuildDangerSignDisplayAsm(byte[] originalTail, out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipStoreXmm0(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		EmitRipMulXmm0(list, fixups2, "value");
		dictionary["done"] = list.Count;
		list.AddRange(new byte[3] { 15, 40, 200 });
		list.AddRange(originalTail);
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static byte[] BuildDangerSignDistanceAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipStoreXmm0(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		EmitRipMulXmm0(list, fixups2, "value");
		dictionary["done"] = list.Count;
		list.AddRange(new byte[3] { 15, 40, 200 });
		list.AddRange(new byte[4] { 72, 141, 75, 40 });
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static XpAggregateHookLayout GetXpAggregateLayout()
	{
		return XpAggregateLayout;
	}

	private static RuntimeProfileHookDescriptor GetXpAggregateDescriptor()
	{
		XpAggregateHookLayout xpAggregateLayout = XpAggregateLayout;
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "XpAggregateGetter";
		runtimeProfileHookDescriptor.Name = "XP Value";
		runtimeProfileHookDescriptor.Signature = "4C 8B C1 8B 89 88 00 00 00 85 C9 74 ? 83 F9 01 74 ? 0F 57 C0 C3 49 8D 50 70 49 8D 48 58 E9 ? ? ? ? 41 8B 90 8C 00 00 00";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 9;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[9] { 76, 139, 193, 139, 137, 136, 0, 0, 0 };
		runtimeProfileHookDescriptor.ToggleOffset = xpAggregateLayout.ToggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = xpAggregateLayout.ValueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = xpAggregateLayout.CaptureOffset;
		runtimeProfileHookDescriptor.ObjectPointerOffset = xpAggregateLayout.ObjectPointerOffset;
		runtimeProfileHookDescriptor.MinimumSize = xpAggregateLayout.MinimumSize;
		runtimeProfileHookDescriptor.Asm = xpAggregateLayout.Asm;
		return runtimeProfileHookDescriptor;
	}

	private static XpAggregateHookLayout BuildXpAggregateLayout()
	{
		List<byte> code = new List<byte>();
		Dictionary<string, int> labels = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		Action<string> action = delegate(string label)
		{
			labels[label] = code.Count;
		};
		EmitRipStoreRcx(code, fixups2, "objectPointer");
		code.AddRange(new byte[6] { 139, 129, 140, 0, 0, 0 });
		EmitRipStoreEax(code, fixups2, "capture");
		EmitRipCmpByteImm(code, fixups2, "toggle", 1);
		EmitJne(code, fixups, "original");
		EmitRipLoadEdx(code, fixups2, "value");
		code.AddRange(new byte[6] { 137, 145, 140, 0, 0, 0 });
		code.AddRange(new byte[10] { 199, 129, 136, 0, 0, 0, 0, 0, 0, 0 });
		EmitJmp(code, fixups, "original");
		action("original");
		code.AddRange(new byte[3] { 76, 139, 193 });
		code.AddRange(new byte[6] { 139, 137, 136, 0, 0, 0 });
		int value = Align4(code.Count + 5);
		int num = value++;
		value = Align4(value);
		int num2 = value;
		value += 4;
		int num3 = value;
		value += 4;
		value = Align8(value);
		int num4 = value;
		value += 8;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("toggle", num);
		dictionary.Add("value", num2);
		dictionary.Add("capture", num3);
		dictionary.Add("objectPointer", num4);
		Dictionary<string, int> labels2 = dictionary;
		PatchRelativeFixups(code, fixups, labels);
		PatchRelativeFixups(code, fixups2, labels2);
		XpAggregateHookLayout xpAggregateHookLayout = new XpAggregateHookLayout();
		xpAggregateHookLayout.Asm = code.ToArray();
		xpAggregateHookLayout.ToggleOffset = num;
		xpAggregateHookLayout.ValueOffset = num2;
		xpAggregateHookLayout.CaptureOffset = num3;
		xpAggregateHookLayout.ObjectPointerOffset = num4;
		xpAggregateHookLayout.MinimumSize = value;
		return xpAggregateHookLayout;
	}

	private static RuntimeProfileHookDescriptor GetSkillTreeWideEditDescriptor()
	{
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "SkillTreeWideEdit";
		runtimeProfileHookDescriptor.Name = "Skill Tree Wide Edit";
		runtimeProfileHookDescriptor.Signature = "40 ? 48 83 EC ? 48 8B ? ? 33 D2 0F 29";
		runtimeProfileHookDescriptor.MatchOffset = 32;
		runtimeProfileHookDescriptor.HookSize = 5;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[5] { 243, 15, 16, 115, 56 };
		runtimeProfileHookDescriptor.ToggleOffset = 27;
		runtimeProfileHookDescriptor.ValueOffset = 28;
		runtimeProfileHookDescriptor.MinimumSize = 32;
		runtimeProfileHookDescriptor.Asm = new byte[22]
		{
			243, 15, 16, 115, 56, 128, 61, 15, 0, 0,
			0, 1, 117, 8, 243, 15, 16, 53, 6, 0,
			0, 0
		};
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetGravityDescriptor()
	{
		GravityHookLayout gravityAllAxesLayout = GravityAllAxesLayout;
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "Gravity";
		runtimeProfileHookDescriptor.Name = "Gravity";
		runtimeProfileHookDescriptor.Signature = "F3 0F 10 4F 04 0F 28 C1 F3 0F 59 4B 08 F3 0F 59 43 04 F3 0F 11 43 04 F3 0F 11 4B 08 F3 0F 10 4F 04 0F 28 C1 F3 0F 59 4B 10 F3 0F 59 43 14 F3 0F 11 4B 10 F3 0F 11 43 14 F3 0F 10 57 04 0F 28 C2 F3 0F 59 53 1C F3 0F 59 43 20 F3 0F 11 53 1C F3 0F 11 43 20 F3 0F 10 4F 04 0F 28 C1 F3 0F 59 4B 28 F3 0F 59 43 2C F3 0F 11 4B 28 F3 0F 11 43 2C";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 112;
		runtimeProfileHookDescriptor.ExpectedOriginal = GravityAllAxesOriginal;
		runtimeProfileHookDescriptor.ToggleOffset = gravityAllAxesLayout.ToggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = gravityAllAxesLayout.ValueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = gravityAllAxesLayout.CaptureOffset;
		runtimeProfileHookDescriptor.MinimumSize = gravityAllAxesLayout.MinimumSize;
		runtimeProfileHookDescriptor.Asm = gravityAllAxesLayout.Asm;
		return runtimeProfileHookDescriptor;
	}

	private static GravityHookLayout GetGravityAllAxesLayout()
	{
		return GravityAllAxesLayout;
	}

	private static GravityHookLayout BuildGravityAllAxesLayout()
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> labels = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> list2 = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> list3 = new List<ProfileAsmFixup>();
		EmitGravityScaleBlock(list, labels, list2, list3, "scalePairA", 8, 4, 4, 8, useXmm2: false);
		EmitGravityScaleBlock(list, labels, list2, list3, "scalePairB", 16, 20, 16, 20, useXmm2: false);
		EmitGravityScaleBlock(list, labels, list2, list3, "scalePairC", 28, 32, 28, 32, useXmm2: true);
		EmitGravityScaleBlock(list, labels, list2, list3, "scalePairD", 40, 44, 40, 44, useXmm2: false);
		int num = Align4(list.Count + 5);
		int num2 = num++;
		int num3 = num;
		num += 4;
		int num4 = num;
		num += 4;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("toggle", num2);
		dictionary.Add("value", num3);
		dictionary.Add("capture", num4);
		Dictionary<string, int> labels2 = dictionary;
		PatchRelativeFixups(list, list2, labels);
		PatchRelativeFixups(list, list3, labels2);
		GravityHookLayout gravityHookLayout = new GravityHookLayout();
		gravityHookLayout.Asm = list.ToArray();
		gravityHookLayout.ToggleOffset = num2;
		gravityHookLayout.ValueOffset = num3;
		gravityHookLayout.CaptureOffset = num4;
		gravityHookLayout.MinimumSize = num;
		return gravityHookLayout;
	}

	private static void EmitGravityScaleBlock(List<byte> code, Dictionary<string, int> labels, List<ProfileAsmFixup> jumps, List<ProfileAsmFixup> dataRefs, string noScaleLabel, byte firstMulOffset, byte secondMulOffset, byte firstStoreOffset, byte secondStoreOffset, bool useXmm2)
	{
		if (useXmm2)
		{
			code.AddRange(new byte[5] { 243, 15, 16, 87, 4 });
			EmitRipCmpByteImm(code, dataRefs, "toggle", 1);
			EmitJne(code, jumps, noScaleLabel);
			EmitRipMulXmm2(code, dataRefs, "value");
		}
		else
		{
			code.AddRange(new byte[5] { 243, 15, 16, 79, 4 });
			if (firstMulOffset == 8)
			{
				EmitRipStoreXmm1(code, dataRefs, "capture");
			}
			EmitRipCmpByteImm(code, dataRefs, "toggle", 1);
			EmitJne(code, jumps, noScaleLabel);
			EmitRipMulXmm1(code, dataRefs, "value");
		}
		labels[noScaleLabel] = code.Count;
		if (useXmm2)
		{
			code.AddRange(new byte[3] { 15, 40, 194 });
			code.AddRange(new byte[5] { 243, 15, 89, 83, firstMulOffset });
			code.AddRange(new byte[5] { 243, 15, 89, 67, secondMulOffset });
			code.AddRange(new byte[5] { 243, 15, 17, 83, firstStoreOffset });
			code.AddRange(new byte[5] { 243, 15, 17, 67, secondStoreOffset });
		}
		else
		{
			code.AddRange(new byte[3] { 15, 40, 193 });
			code.AddRange(new byte[5] { 243, 15, 89, 75, firstMulOffset });
			code.AddRange(new byte[5] { 243, 15, 89, 67, secondMulOffset });
			code.AddRange(new byte[5] { 243, 15, 17, 75, firstStoreOffset });
			code.AddRange(new byte[5] { 243, 15, 17, 67, secondStoreOffset });
		}
	}

	private static RuntimeProfileHookDescriptor GetNoWaterDragDescriptor()
	{
		SimpleToggleHookLayout noWaterDragLayout = NoWaterDragLayout;
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "NoWaterDrag";
		runtimeProfileHookDescriptor.Name = "No Water Drag";
		runtimeProfileHookDescriptor.Signature = "48 8B ? F3 0F ? ? ? 53 55";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 8;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[8] { 72, 139, 196, 243, 15, 17, 72, 16 };
		runtimeProfileHookDescriptor.ToggleOffset = noWaterDragLayout.ToggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.MinimumSize = noWaterDragLayout.MinimumSize;
		runtimeProfileHookDescriptor.Asm = noWaterDragLayout.Asm;
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetFreeClothingDescriptor()
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		list.AddRange(new byte[2] { 49, 201 });
		EmitJmp(list, fixups, "done");
		dictionary["original"] = list.Count;
		list.AddRange(new byte[6] { 139, 136, 164, 0, 0, 0 });
		dictionary["done"] = list.Count;
		int minimumSize = Align4(list.Count + 5);
		int num = minimumSize++;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", num);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "FreeClothing";
		runtimeProfileHookDescriptor.Name = "Free Clothing";
		runtimeProfileHookDescriptor.Signature = "8B 88 A4 00 00 00 89 4D";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 6;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[6] { 139, 136, 164, 0, 0, 0 };
		runtimeProfileHookDescriptor.ToggleOffset = num;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = list.ToArray();
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetWaypointPointerDescriptor()
	{
		List<byte> list = new List<byte>();
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		byte[] array = new byte[9] { 243, 69, 15, 16, 151, 48, 2, 0, 0 };
		EmitRipStoreR15(list, fixups, "waypointPointer");
		list.AddRange(array);
		int num = Align8(list.Count + 5);
		int num2 = num;
		num += 8;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("waypointPointer", num2);
		Dictionary<string, int> labels = dictionary;
		PatchRelativeFixups(list, fixups, labels);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "TeleportWaypointPointer";
		runtimeProfileHookDescriptor.Name = "Teleport Waypoint Pointer";
		runtimeProfileHookDescriptor.Signature = "F3 45 0F 10 97 30 02 00 00";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = array.Length;
		runtimeProfileHookDescriptor.ExpectedOriginal = array;
		runtimeProfileHookDescriptor.ToggleOffset = -1;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.ObjectPointerOffset = num2;
		runtimeProfileHookDescriptor.MinimumSize = num;
		runtimeProfileHookDescriptor.Asm = list.ToArray();
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetWaypointDestinationCaptureDescriptor(int index)
	{
		List<byte> list = new List<byte>();
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		bool flag = false;
		byte[] array;
		string key;
		string name;
		string signature;
		int matchOffset;
		switch (index)
		{
		default:
			throw new ArgumentOutOfRangeException("index");
		case 0:
			array = new byte[10] { 15, 40, 68, 36, 80, 15, 17, 68, 36, 104 };
			key = "TeleportSatNavRouteCapture";
			name = "Teleport SatNav Route Capture";
			signature = "48 8D 0D ? ? ? ? 48 89 4C 24 60 0F 28 44 24 50 0F 11 44 24 68 48 8D 4C 24 60 48 89 4D 98 48 89 5C 24 50 48 C7 44 24 58 12 00 00 00 4C 8D 44 24 60 48 8D 54 24 50 48 8B C8 E8 ? ? ? ? EB 03 49 8B C5 48 8B D0 48 8B CF E8 ? ? ? ?";
			matchOffset = 12;
			break;
		case 1:
			array = new byte[10] { 15, 40, 68, 36, 80, 15, 17, 68, 36, 104 };
			key = "TeleportSatNavStoreCapture";
			name = "Teleport SatNav Store Capture";
			signature = "4C 89 64 24 60 0F 28 44 24 50 0F 11 44 24 68 48 8D 4C 24 60 48 89 4D 98 48 8D 0D ? ? ? ? 48 89 4C 24 50 48 C7 44 24 58 16 00 00 00 4C 8D 44 24 60 48 8D 54 24 50 48 8B C8 E8 ? ? ? ? EB 03 49 8B C5 48 8B D0 48 8B CB E8 ? ? ? ?";
			matchOffset = 5;
			break;
		case 2:
			array = new byte[11]
			{
				65, 15, 40, 0, 15, 17, 130, 96, 7, 0,
				0
			};
			key = "TeleportCurrentDestinationSetter";
			name = "Teleport Current Destination Setter";
			signature = "41 0F 28 00 0F 11 82 60 07 00 00 C3";
			matchOffset = 0;
			flag = true;
			break;
		case 3:
			array = new byte[11]
			{
				65, 15, 40, 0, 15, 17, 130, 144, 0, 0,
				0
			};
			key = "TeleportNavigationDestinationSetter";
			name = "Teleport Navigation Destination Setter";
			signature = "41 0F 28 00 0F 11 82 90 00 00 00 C3";
			matchOffset = 0;
			flag = true;
			break;
		}
		list.AddRange(array);
		EmitRipStoreXmm0Vector(list, fixups, "waypointPosition");
		if (flag)
		{
			EmitRipStoreRdx(list, fixups, "destinationObject");
		}
		int num = Align8(list.Count + 5);
		int num2 = num;
		num += 16;
		int num3 = -1;
		if (flag)
		{
			num = Align8(num);
			num3 = num;
			num += 8;
		}
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("waypointPosition", num2);
		Dictionary<string, int> dictionary2 = dictionary;
		if (flag)
		{
			dictionary2["destinationObject"] = num3;
		}
		PatchRelativeFixups(list, fixups, dictionary2);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = key;
		runtimeProfileHookDescriptor.Name = name;
		runtimeProfileHookDescriptor.Signature = signature;
		runtimeProfileHookDescriptor.MatchOffset = matchOffset;
		runtimeProfileHookDescriptor.HookSize = array.Length;
		runtimeProfileHookDescriptor.ExpectedOriginal = array;
		runtimeProfileHookDescriptor.ToggleOffset = -1;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.CaptureOffset = num2;
		runtimeProfileHookDescriptor.ObjectPointerOffset = num3;
		runtimeProfileHookDescriptor.MinimumSize = num;
		runtimeProfileHookDescriptor.Asm = list.ToArray();
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetCurrentDestinationPointerDescriptor()
	{
		List<byte> list = new List<byte>();
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		byte[] array = new byte[7] { 72, 141, 130, 96, 7, 0, 0 };
		EmitRipStoreRdx(list, fixups, "destinationObject");
		list.AddRange(array);
		int num = Align8(list.Count + 5);
		int num2 = num;
		num += 8;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("destinationObject", num2);
		Dictionary<string, int> labels = dictionary;
		PatchRelativeFixups(list, fixups, labels);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "TeleportCurrentDestinationPointer";
		runtimeProfileHookDescriptor.Name = "Teleport Current Destination Pointer";
		runtimeProfileHookDescriptor.Signature = "48 8D 82 60 07 00 00 C3";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = array.Length;
		runtimeProfileHookDescriptor.ExpectedOriginal = array;
		runtimeProfileHookDescriptor.ToggleOffset = -1;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.ObjectPointerOffset = num2;
		runtimeProfileHookDescriptor.MinimumSize = num;
		runtimeProfileHookDescriptor.Asm = list.ToArray();
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetWaypointRouteVectorDescriptor(int index)
	{
		List<byte> list = new List<byte>();
		List<ProfileAsmFixup> list2 = new List<ProfileAsmFixup>();
		byte[] array;
		string key;
		string name;
		string signature;
		int matchOffset;
		Action<List<byte>, List<ProfileAsmFixup>, string> action;
		switch (index)
		{
		default:
			throw new ArgumentOutOfRangeException("index");
		case 0:
			array = new byte[7] { 15, 16, 131, 128, 0, 0, 0 };
			key = "TeleportRouteVectorA";
			name = "Teleport Route Vector A";
			signature = "BA 02 00 00 00 44 3B C2 75 30 0F 10 83 80 00 00 00 0F 28 D8 0F C2 83 90 00 00 00 04 0F 50 C0";
			matchOffset = 10;
			action = EmitRipStoreXmm0Vector;
			break;
		case 1:
			array = new byte[7] { 15, 16, 139, 144, 0, 0, 0 };
			key = "TeleportRouteVectorB";
			name = "Teleport Route Vector B";
			signature = "0F 10 8B 90 00 00 00 E9 ? ? ? ? 0F 28 4D 10 B8 01 00 00 00 EB 5D";
			matchOffset = 0;
			action = EmitRipStoreXmm1Vector;
			break;
		case 2:
			array = new byte[7] { 15, 16, 147, 160, 0, 0, 0 };
			key = "TeleportRouteVectorC";
			name = "Teleport Route Vector C";
			signature = "0F 10 A3 80 00 00 00 0F 10 AB 90 00 00 00 0F 28 C4 0F 10 93 A0 00 00 00 0F 28 DC 0F C2 C5 04 0F 50 C0";
			matchOffset = 17;
			action = EmitRipStoreXmm2Vector;
			break;
		}
		list.AddRange(array);
		action(list, list2, "waypointPosition");
		EmitRipStoreRbx(list, list2, "routeObject");
		int num = Align8(list.Count + 5);
		int num2 = num;
		num += 16;
		num = Align8(num);
		int num3 = num;
		num += 8;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("waypointPosition", num2);
		dictionary.Add("routeObject", num3);
		Dictionary<string, int> labels = dictionary;
		PatchRelativeFixups(list, list2, labels);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = key;
		runtimeProfileHookDescriptor.Name = name;
		runtimeProfileHookDescriptor.Signature = signature;
		runtimeProfileHookDescriptor.MatchOffset = matchOffset;
		runtimeProfileHookDescriptor.HookSize = array.Length;
		runtimeProfileHookDescriptor.ExpectedOriginal = array;
		runtimeProfileHookDescriptor.ToggleOffset = -1;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.CaptureOffset = num2;
		runtimeProfileHookDescriptor.ObjectPointerOffset = num3;
		runtimeProfileHookDescriptor.MinimumSize = num;
		runtimeProfileHookDescriptor.Asm = list.ToArray();
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetNavigationDestinationPointerDescriptor(int index)
	{
		List<byte> list = new List<byte>();
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		byte[] array;
		string key;
		string name;
		string signature;
		int matchOffset;
		switch (index)
		{
		default:
			throw new ArgumentOutOfRangeException("index");
		case 0:
			array = new byte[7] { 72, 141, 130, 144, 0, 0, 0 };
			key = "TeleportNavigationDestinationPointer";
			name = "Teleport Navigation Destination Pointer";
			signature = "48 8D 82 90 00 00 00 C3";
			matchOffset = 0;
			break;
		case 1:
			array = new byte[7] { 72, 141, 130, 144, 0, 0, 0 };
			key = "TeleportNavigationDestinationPointerSafe";
			name = "Teleport Navigation Destination Pointer Safe";
			signature = "33 C9 48 8D 82 90 00 00 00 48 85 D2 48 0F 44 C1 C3";
			matchOffset = 2;
			break;
		}
		EmitRipStoreRdx(list, fixups, "destinationObject");
		list.AddRange(array);
		int num = Align8(list.Count + 5);
		int num2 = num;
		num += 8;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("destinationObject", num2);
		Dictionary<string, int> labels = dictionary;
		PatchRelativeFixups(list, fixups, labels);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = key;
		runtimeProfileHookDescriptor.Name = name;
		runtimeProfileHookDescriptor.Signature = signature;
		runtimeProfileHookDescriptor.MatchOffset = matchOffset;
		runtimeProfileHookDescriptor.HookSize = array.Length;
		runtimeProfileHookDescriptor.ExpectedOriginal = array;
		runtimeProfileHookDescriptor.ToggleOffset = -1;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.ObjectPointerOffset = num2;
		runtimeProfileHookDescriptor.MinimumSize = num;
		runtimeProfileHookDescriptor.Asm = list.ToArray();
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetSatNavRouteObjectDescriptor()
	{
		List<byte> list = new List<byte>();
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		byte[] array = new byte[8] { 51, 192, 57, 129, 144, 0, 0, 0 };
		EmitRipStoreRcx(list, fixups, "satNavObject");
		list.AddRange(array);
		int num = Align8(list.Count + 5);
		int num2 = num;
		num += 8;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("satNavObject", num2);
		Dictionary<string, int> labels = dictionary;
		PatchRelativeFixups(list, fixups, labels);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "TeleportSatNavRouteObject";
		runtimeProfileHookDescriptor.Name = "Teleport SatNav Route Object";
		runtimeProfileHookDescriptor.Signature = "33 C0 39 81 90 00 00 00 0F 9E C0 C3";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = array.Length;
		runtimeProfileHookDescriptor.ExpectedOriginal = array;
		runtimeProfileHookDescriptor.ToggleOffset = -1;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.ObjectPointerOffset = num2;
		runtimeProfileHookDescriptor.MinimumSize = num;
		runtimeProfileHookDescriptor.Asm = list.ToArray();
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetWaypointCopyDescriptor(int index)
	{
		List<byte> list = new List<byte>();
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		byte[] array = new byte[7] { 15, 16, 139, 48, 2, 0, 0 };
		list.AddRange(array);
		EmitRipStoreXmm1Vector(list, fixups, "waypointPosition");
		int num = Align8(list.Count + 5);
		int num2 = num;
		num += 16;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("waypointPosition", num2);
		Dictionary<string, int> labels = dictionary;
		PatchRelativeFixups(list, fixups, labels);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "TeleportWaypointCopy" + index.ToString(CultureInfo.InvariantCulture);
		runtimeProfileHookDescriptor.Name = "Teleport Waypoint Copy " + (index + 1).ToString(CultureInfo.InvariantCulture);
		runtimeProfileHookDescriptor.Signature = "0F 10 8B 30 02 00 00 0F 11 8F 30 02 00 00";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = array.Length;
		runtimeProfileHookDescriptor.ExpectedOriginal = array;
		runtimeProfileHookDescriptor.ToggleOffset = -1;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.CaptureOffset = num2;
		runtimeProfileHookDescriptor.MinimumSize = num;
		runtimeProfileHookDescriptor.Asm = list.ToArray();
		return runtimeProfileHookDescriptor;
	}

	private static RuntimeProfileHookDescriptor GetMissionTimerScaleDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int minimumSize;
		byte[] asm = BuildMissionTimerScaleAsm(out toggleOffset, out valueOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "MissionTimerScale";
		runtimeProfileHookDescriptor.Name = "Mission Timer Scale";
		runtimeProfileHookDescriptor.Signature = "F3 0F ? ? F3 0F ? ? ? ? ? ? 0F 2F ? 0F 87 ? ? ? ? C7 ? ? ? ? ? 00 00 00 00";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 12;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[12]
		{
			243, 15, 92, 199, 243, 15, 17, 131, 76, 4,
			0, 0
		};
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildMissionTimerScaleAsm(out int toggleOffset, out int valueOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		list.AddRange(new byte[3] { 15, 40, 207 });
		EmitRipMulXmm1(list, fixups2, "value");
		list.AddRange(new byte[4] { 243, 15, 92, 193 });
		list.AddRange(new byte[8] { 243, 15, 17, 131, 76, 4, 0, 0 });
		EmitJmp(list, fixups, "done");
		dictionary["original"] = list.Count;
		list.AddRange(new byte[4] { 243, 15, 92, 199 });
		list.AddRange(new byte[8] { 243, 15, 17, 131, 76, 4, 0, 0 });
		dictionary["done"] = list.Count;
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = valueOffset + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetRaceTimerScaleDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int minimumSize;
		byte[] asm = BuildRaceTimerScaleAsm(out toggleOffset, out valueOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "RaceTimerScale";
		runtimeProfileHookDescriptor.Name = "Race Timer Scale";
		runtimeProfileHookDescriptor.Signature = "40 ? 48 83 EC ? 48 8B ? 48 8B ? 0F 29 ? ? ? 0F 28 ? FF 50 ? 0F 57";
		runtimeProfileHookDescriptor.MatchOffset = 29;
		runtimeProfileHookDescriptor.HookSize = 8;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[8] { 243, 15, 90, 206, 242, 15, 88, 200 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildRaceTimerScaleAsm(out int toggleOffset, out int valueOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		list.AddRange(new byte[3] { 15, 40, 206 });
		EmitRipMulXmm1(list, fixups2, "value");
		list.AddRange(new byte[4] { 243, 15, 90, 201 });
		list.AddRange(new byte[4] { 242, 15, 88, 200 });
		EmitJmp(list, fixups, "done");
		dictionary["original"] = list.Count;
		list.AddRange(new byte[4] { 243, 15, 90, 206 });
		list.AddRange(new byte[4] { 242, 15, 88, 200 });
		dictionary["done"] = list.Count;
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = valueOffset + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetTimeOfDayDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildTimeOfDayAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "TimeOfDayUpdate";
		runtimeProfileHookDescriptor.Name = "Time of Day Update";
		runtimeProfileHookDescriptor.Signature = "F3 0F 11 73 64 0F 28 74 24 40 48 83 C4 50 5B C3";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 5;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[5] { 243, 15, 17, 115, 100 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildTimeOfDayAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipStoreXmm6(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		EmitRipLoadXmm6(list, fixups2, "value");
		list.AddRange(new byte[4] { 198, 67, 120, 1 });
		list.AddRange(new byte[4] { 198, 67, 122, 1 });
		dictionary["original"] = list.Count;
		list.AddRange(new byte[5] { 243, 15, 17, 115, 100 });
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetTimeOfDaySetterDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildTimeOfDaySetterAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "TimeOfDaySetter";
		runtimeProfileHookDescriptor.Name = "Time of Day Setter";
		runtimeProfileHookDescriptor.Signature = "80 79 7A 00 75 05 F3 0F 11 49 64 C3";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 11;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[11]
		{
			128, 121, 122, 0, 117, 5, 243, 15, 17, 73,
			100
		};
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildTimeOfDaySetterAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipStoreXmm1(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		EmitRipLoadXmm1(list, fixups2, "value");
		list.AddRange(new byte[5] { 243, 15, 17, 73, 100 });
		list.AddRange(new byte[4] { 198, 65, 120, 1 });
		list.AddRange(new byte[4] { 198, 65, 122, 1 });
		EmitJmp(list, fixups, "done");
		dictionary["original"] = list.Count;
		list.AddRange(new byte[4] { 128, 121, 122, 0 });
		EmitJne(list, fixups, "done");
		list.AddRange(new byte[5] { 243, 15, 17, 73, 100 });
		dictionary["done"] = list.Count;
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetTimeOfDayGetterDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildTimeOfDayGetterAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "TimeOfDayGetter";
		runtimeProfileHookDescriptor.Name = "Time of Day Getter";
		runtimeProfileHookDescriptor.Signature = "F3 0F 10 41 64 C3 CC CC CC CC CC CC CC CC CC CC B0 07 C3";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 5;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[5] { 243, 15, 16, 65, 100 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildTimeOfDayGetterAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		list.AddRange(new byte[5] { 243, 15, 16, 65, 100 });
		EmitRipStoreXmm0(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		EmitRipLoadXmm0(list, fixups2, "value");
		list.AddRange(new byte[5] { 243, 15, 17, 65, 100 });
		list.AddRange(new byte[4] { 198, 65, 120, 1 });
		list.AddRange(new byte[4] { 198, 65, 122, 1 });
		dictionary["done"] = list.Count;
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetFovSliderDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int minimumSize;
		byte[] asm = BuildFovSliderAsm(out toggleOffset, out valueOffset, out captureOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "FovSlider";
		runtimeProfileHookDescriptor.Name = "FOV Slider";
		runtimeProfileHookDescriptor.Signature = "0F 10 01 B0 01 0F 28 74 24 10 F3 0F 11 3A";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 5;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[5] { 15, 16, 1, 176, 1 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildFovSliderAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		list.AddRange(new byte[3] { 15, 16, 1 });
		list.AddRange(new byte[2] { 176, 1 });
		EmitCmpRcxDwordOffsetImm(list, 38, 2070364822u);
		EmitJe(list, fixups, "fovCandidate");
		EmitCmpRcxDwordOffsetImm(list, 38, 2706195540u);
		EmitJne(list, fixups, "done");
		dictionary["fovCandidate"] = list.Count;
		EmitRipStoreXmm7(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "done");
		EmitRipLoadXmm7(list, fixups2, "value");
		dictionary["done"] = list.Count;
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = (captureOffset = valueOffset + 4) + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		dictionary2.Add("capture", captureOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetNoBuildLimitDescriptor()
	{
		int toggleOffset;
		int minimumSize;
		byte[] asm = BuildNoBuildLimitAsm(out toggleOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "NoBuildLimit";
		runtimeProfileHookDescriptor.Name = "No Build Limit";
		runtimeProfileHookDescriptor.Signature = "E8 ? ? ? ? F3 0F ? ? ? 48 8B ? ? ? 48 8B";
		runtimeProfileHookDescriptor.MatchOffset = 5;
		runtimeProfileHookDescriptor.HookSize = 5;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[5] { 243, 15, 17, 69, 0 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildNoBuildLimitAsm(out int toggleOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		list.AddRange(new byte[3] { 15, 87, 192 });
		dictionary["original"] = list.Count;
		list.AddRange(new byte[5] { 243, 15, 17, 69, 0 });
		int num = Align4(list.Count + 5);
		toggleOffset = num++;
		minimumSize = num;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetFreezeAIDescriptor()
	{
		int toggleOffset;
		int vehiclePointerSlotOffset;
		int minimumSize;
		byte[] asm = BuildFreezeAIAsm(out toggleOffset, out vehiclePointerSlotOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "FreezeAI";
		runtimeProfileHookDescriptor.Name = "Freeze AI";
		runtimeProfileHookDescriptor.Signature = "F3 0F 10 91 40 06 00 00 F3 0F 10 89 4C 02 00 00 F3 0F 10 81 B0 01 00 00 F3 0F 5C CA F3 0F 58 81 5C 01 00 00 F3 0F 5C C2 F3 0F 5E C1";
		runtimeProfileHookDescriptor.MatchOffset = 28;
		runtimeProfileHookDescriptor.HookSize = 8;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[8] { 243, 15, 88, 129, 92, 1, 0, 0 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.ObjectPointerOffset = vehiclePointerSlotOffset;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildFreezeAIAsm(out int toggleOffset, out int vehiclePointerSlotOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		list.AddRange(new byte[1] { 86 });
		list.AddRange(new byte[3] { 72, 139, 53 });
		AddRelativeFixup(list, fixups2, "vehiclePointerSlot");
		list.AddRange(new byte[3] { 72, 133, 246 });
		EmitJe(list, fixups, "restore");
		list.AddRange(new byte[3] { 72, 139, 54 });
		list.AddRange(new byte[3] { 72, 133, 246 });
		EmitJe(list, fixups, "restore");
		list.AddRange(new byte[7] { 72, 141, 182, 112, 5, 0, 0 });
		list.AddRange(new byte[3] { 72, 57, 206 });
		EmitJe(list, fixups, "restore");
		list.AddRange(new byte[10] { 199, 129, 176, 250, 255, 255, 0, 0, 0, 0 });
		list.AddRange(new byte[10] { 199, 129, 180, 250, 255, 255, 0, 0, 0, 0 });
		list.AddRange(new byte[10] { 199, 129, 184, 250, 255, 255, 0, 0, 0, 0 });
		dictionary["restore"] = list.Count;
		list.AddRange(new byte[1] { 94 });
		dictionary["original"] = list.Count;
		list.AddRange(new byte[8] { 243, 15, 88, 129, 92, 1, 0, 0 });
		int value = Align4(list.Count + 5);
		toggleOffset = value++;
		value = (vehiclePointerSlotOffset = Align8(value)) + 8;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("vehiclePointerSlot", vehiclePointerSlotOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetNoClipDescriptor()
	{
		int toggleOffset;
		int minimumSize;
		byte[] asm = BuildNoClipAsm(out toggleOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "NoClipBypassPhysicsGetter";
		runtimeProfileHookDescriptor.Name = "No Clip";
		runtimeProfileHookDescriptor.Signature = "48 8B 41 10 0F B6 80 A8 04 00 00 C3";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 12;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[12]
		{
			72, 139, 65, 16, 15, 182, 128, 168, 4, 0,
			0, 195
		};
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = -1;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildNoClipAsm(out int toggleOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		list.AddRange(new byte[5] { 184, 1, 0, 0, 0 });
		list.AddRange(new byte[1] { 195 });
		dictionary["original"] = list.Count;
		list.AddRange(new byte[4] { 72, 139, 65, 16 });
		list.AddRange(new byte[7] { 15, 182, 128, 168, 4, 0, 0 });
		list.AddRange(new byte[1] { 195 });
		int num = Align4(list.Count + 5);
		toggleOffset = num++;
		minimumSize = num;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", toggleOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetSeriesPointsDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int objectPointerOffset;
		int minimumSize;
		byte[] asm = BuildSeriesPointsAsm(out toggleOffset, out valueOffset, out captureOffset, out objectPointerOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "SeriesPoints";
		runtimeProfileHookDescriptor.Name = "Series Points";
		runtimeProfileHookDescriptor.Signature = "89 59 ? 48 83 C4 ? 5B C3 CC CC CC CC CC 44 89";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 7;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[7] { 137, 89, 20, 72, 131, 196, 48 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.ObjectPointerOffset = objectPointerOffset;
		runtimeProfileHookDescriptor.ObjectValueFieldOffset = 20;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildSeriesPointsAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int objectPointerOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipStoreRcx(list, fixups2, "objectPointer");
		list.AddRange(new byte[2] { 137, 29 });
		AddRelativeFixup(list, fixups2, "capture");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		EmitRipLoadEax(list, fixups2, "value");
		list.AddRange(new byte[3] { 137, 65, 20 });
		list.AddRange(new byte[4] { 72, 131, 196, 48 });
		EmitJmp(list, fixups, "done");
		dictionary["original"] = list.Count;
		list.AddRange(new byte[3] { 137, 89, 20 });
		list.AddRange(new byte[4] { 72, 131, 196, 48 });
		dictionary["done"] = list.Count;
		int value = (captureOffset = Align4(list.Count + 5)) + 4;
		value = (objectPointerOffset = Align8(value)) + 8;
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = valueOffset + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("capture", captureOffset);
		dictionary2.Add("objectPointer", objectPointerOffset);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static RuntimeProfileHookDescriptor GetSeriesPointsDisplayDescriptor()
	{
		int toggleOffset;
		int valueOffset;
		int captureOffset;
		int objectPointerOffset;
		int minimumSize;
		byte[] asm = BuildSeriesPointsDisplayAsm(out toggleOffset, out valueOffset, out captureOffset, out objectPointerOffset, out minimumSize);
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "SeriesPointsDisplay";
		runtimeProfileHookDescriptor.Name = "Series Points Display";
		runtimeProfileHookDescriptor.Signature = "8B 1B 48 8B C8 E8 ? ? ? ? 89 5F 20 48 8D 05";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 5;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[5] { 139, 27, 72, 139, 200 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.CaptureOffset = captureOffset;
		runtimeProfileHookDescriptor.ObjectPointerOffset = objectPointerOffset;
		runtimeProfileHookDescriptor.ObjectValueFieldOffset = 32;
		runtimeProfileHookDescriptor.MinimumSize = minimumSize;
		runtimeProfileHookDescriptor.Asm = asm;
		return runtimeProfileHookDescriptor;
	}

	private static byte[] BuildSeriesPointsDisplayAsm(out int toggleOffset, out int valueOffset, out int captureOffset, out int objectPointerOffset, out int minimumSize)
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		list.AddRange(new byte[2] { 139, 27 });
		EmitRipStoreEbx(list, fixups2, "capture");
		EmitRipStoreRdi(list, fixups2, "objectPointer");
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "originalTail");
		EmitRipLoadEbx(list, fixups2, "value");
		dictionary["originalTail"] = list.Count;
		list.AddRange(new byte[3] { 72, 139, 200 });
		int value = (captureOffset = Align4(list.Count + 5)) + 4;
		value = (objectPointerOffset = Align8(value)) + 8;
		toggleOffset = value++;
		valueOffset = Align4(value);
		value = valueOffset + 4;
		minimumSize = value;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("capture", captureOffset);
		dictionary2.Add("objectPointer", objectPointerOffset);
		dictionary2.Add("toggle", toggleOffset);
		dictionary2.Add("value", valueOffset);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		return list.ToArray();
	}

	private static SimpleToggleHookLayout GetNoWaterDragLayout()
	{
		return NoWaterDragLayout;
	}

	private static SimpleToggleHookLayout BuildNoWaterDragLayout()
	{
		List<byte> list = new List<byte>();
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		EmitRipCmpByteImm(list, fixups2, "toggle", 1);
		EmitJne(list, fixups, "original");
		list.AddRange(new byte[1] { 195 });
		dictionary["original"] = list.Count;
		list.AddRange(new byte[8] { 72, 139, 196, 243, 15, 17, 72, 16 });
		int minimumSize = Align4(list.Count + 5);
		int num = minimumSize++;
		Dictionary<string, int> dictionary2 = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary2.Add("toggle", num);
		Dictionary<string, int> labels = dictionary2;
		PatchRelativeFixups(list, fixups, dictionary);
		PatchRelativeFixups(list, fixups2, labels);
		SimpleToggleHookLayout simpleToggleHookLayout = new SimpleToggleHookLayout();
		simpleToggleHookLayout.Asm = list.ToArray();
		simpleToggleHookLayout.ToggleOffset = num;
		simpleToggleHookLayout.MinimumSize = minimumSize;
		return simpleToggleHookLayout;
	}

	private static RuntimeProfileHookDescriptor GetVehicleControlDescriptor(RuntimeProfileFeature feature)
	{
		VehicleControlHookLayout vehicleControlLayout = VehicleControlLayout;
		bool flag = feature == RuntimeProfileFeature.Jump;
		bool flag2 = feature == RuntimeProfileFeature.Boost;
		bool flag3 = feature == RuntimeProfileFeature.DriftMode;
		bool flag4 = feature == RuntimeProfileFeature.Gravity;
		bool flag5 = feature == RuntimeProfileFeature.Acceleration;
		bool flag6 = feature == RuntimeProfileFeature.SuperHandling;
		bool flag7 = feature == RuntimeProfileFeature.LandingStabilizer;
		bool flag8 = feature == RuntimeProfileFeature.SlideCalmer;
		bool flag9 = feature == RuntimeProfileFeature.RoadMagnet;
		bool flag10 = feature == RuntimeProfileFeature.AdaptiveBrake;
		bool flag11 = feature == RuntimeProfileFeature.SpeedTamer;
		bool flag12 = feature == RuntimeProfileFeature.AirLift;
		bool flag13 = feature == RuntimeProfileFeature.BounceCushion;
		bool flag14 = feature == RuntimeProfileFeature.MomentumControl;
		bool flag15 = feature == RuntimeProfileFeature.LeftRightCalm;
		bool flag16 = feature == RuntimeProfileFeature.ForwardBackCalm;
		bool flag17 = feature == RuntimeProfileFeature.SidePush;
		bool flag18 = feature == RuntimeProfileFeature.ForwardPush;
		bool flag19 = feature == RuntimeProfileFeature.VerticalTrim;
		bool flag20 = feature == RuntimeProfileFeature.SideLock;
		bool flag21 = feature == RuntimeProfileFeature.ForwardLock;
		bool flag22 = feature == RuntimeProfileFeature.VerticalHold;
		bool flag23 = feature == RuntimeProfileFeature.MotionFreeze;
		bool flag24 = feature == RuntimeProfileFeature.WheelieBoost;
		bool flag25 = feature == RuntimeProfileFeature.DriftKick;
		bool flag26 = feature == RuntimeProfileFeature.HoverGlide;
		bool flag27 = feature == RuntimeProfileFeature.AirBrake;
		bool flag28 = feature == RuntimeProfileFeature.CornerStabilizer;
		bool flag29 = feature == RuntimeProfileFeature.PlantedBoost;
		bool flag30 = feature == RuntimeProfileFeature.ForwardLaunch;
		bool flag31 = feature == RuntimeProfileFeature.StraightLaunch;
		bool flag32 = feature == RuntimeProfileFeature.DragLaunchAssist;
		bool flag33 = feature == RuntimeProfileFeature.TireBite;
		bool flag34 = feature == RuntimeProfileFeature.GripLock;
		bool flag35 = feature == RuntimeProfileFeature.ForwardGrip;
		bool flag36 = feature == RuntimeProfileFeature.RailGrip;
		bool flag37 = feature == RuntimeProfileFeature.HighSpeedStabilizer;
		bool flag38 = feature == RuntimeProfileFeature.GroundClamp;
		bool flag39 = feature == RuntimeProfileFeature.StabilityRail;
		bool flag40 = feature == RuntimeProfileFeature.AirControl;
		bool flag41 = feature == RuntimeProfileFeature.CornerBite;
		bool flag42 = feature == RuntimeProfileFeature.SpinRecovery;
		string name = "Super Brake";
		int toggleOffset = vehicleControlLayout.SpeedToggleOffset;
		int valueOffset = vehicleControlLayout.SpeedValueOffset;
		if (flag4)
		{
			name = "Gravity Downforce";
			toggleOffset = vehicleControlLayout.GravityToggleOffset;
			valueOffset = vehicleControlLayout.GravityValueOffset;
		}
		else if (flag)
		{
			name = "Jump";
			toggleOffset = vehicleControlLayout.JumpToggleOffset;
			valueOffset = vehicleControlLayout.JumpValueOffset;
		}
		else if (flag2)
		{
			name = "Boost";
			toggleOffset = vehicleControlLayout.BoostToggleOffset;
			valueOffset = vehicleControlLayout.BoostValueOffset;
		}
		else if (flag3)
		{
			name = "Drift Mode";
			toggleOffset = vehicleControlLayout.DriftModeToggleOffset;
			valueOffset = vehicleControlLayout.DriftModeValueOffset;
		}
		else if (flag6)
		{
			name = "Super Handling";
			toggleOffset = vehicleControlLayout.HandlingToggleOffset;
			valueOffset = vehicleControlLayout.HandlingValueOffset;
		}
		else if (flag7)
		{
			name = "Landing Stabilizer";
			toggleOffset = vehicleControlLayout.StabilizerToggleOffset;
			valueOffset = vehicleControlLayout.StabilizerValueOffset;
		}
		else if (flag8)
		{
			name = "Slide Calmer";
			toggleOffset = vehicleControlLayout.SlideToggleOffset;
			valueOffset = vehicleControlLayout.SlideValueOffset;
		}
		else if (flag9)
		{
			name = "Road Magnet";
			toggleOffset = vehicleControlLayout.RoadMagnetToggleOffset;
			valueOffset = vehicleControlLayout.RoadMagnetValueOffset;
		}
		else if (flag10)
		{
			name = "Adaptive Brake";
		}
		else if (flag5)
		{
			name = "Acceleration";
		}
		else if (flag11)
		{
			name = "Speed Tamer";
			toggleOffset = vehicleControlLayout.SpeedTamerToggleOffset;
			valueOffset = vehicleControlLayout.SpeedTamerValueOffset;
		}
		else if (flag12)
		{
			name = "Air Lift";
			toggleOffset = vehicleControlLayout.AirLiftToggleOffset;
			valueOffset = vehicleControlLayout.AirLiftValueOffset;
		}
		else if (flag13)
		{
			name = "Bounce Cushion";
			toggleOffset = vehicleControlLayout.BounceCushionToggleOffset;
			valueOffset = vehicleControlLayout.BounceCushionValueOffset;
		}
		else if (flag14)
		{
			name = "Momentum Control";
			toggleOffset = vehicleControlLayout.MomentumToggleOffset;
			valueOffset = vehicleControlLayout.MomentumValueOffset;
		}
		else if (flag15)
		{
			name = "Left Right Calm";
			toggleOffset = vehicleControlLayout.LeftRightToggleOffset;
			valueOffset = vehicleControlLayout.LeftRightValueOffset;
		}
		else if (flag16)
		{
			name = "Forward Back Calm";
			toggleOffset = vehicleControlLayout.ForwardBackToggleOffset;
			valueOffset = vehicleControlLayout.ForwardBackValueOffset;
		}
		else if (flag17)
		{
			name = "Side Push";
			toggleOffset = vehicleControlLayout.SidePushToggleOffset;
			valueOffset = vehicleControlLayout.SidePushValueOffset;
		}
		else if (flag18)
		{
			name = "Forward Push";
			toggleOffset = vehicleControlLayout.ForwardPushToggleOffset;
			valueOffset = vehicleControlLayout.ForwardPushValueOffset;
		}
		else if (flag19)
		{
			name = "Vertical Trim";
			toggleOffset = vehicleControlLayout.VerticalTrimToggleOffset;
			valueOffset = vehicleControlLayout.VerticalTrimValueOffset;
		}
		else if (flag20)
		{
			name = "Side Lock";
			toggleOffset = vehicleControlLayout.SideLockToggleOffset;
			valueOffset = vehicleControlLayout.SideLockValueOffset;
		}
		else if (flag21)
		{
			name = "Forward Lock";
			toggleOffset = vehicleControlLayout.ForwardLockToggleOffset;
			valueOffset = vehicleControlLayout.ForwardLockValueOffset;
		}
		else if (flag22)
		{
			name = "Vertical Hold";
			toggleOffset = vehicleControlLayout.VerticalHoldToggleOffset;
			valueOffset = vehicleControlLayout.VerticalHoldValueOffset;
		}
		else if (flag23)
		{
			name = "Motion Freeze";
			toggleOffset = vehicleControlLayout.MotionFreezeToggleOffset;
			valueOffset = vehicleControlLayout.MotionFreezeValueOffset;
		}
		else if (flag24)
		{
			name = "Wheelie Boost";
			toggleOffset = vehicleControlLayout.WheelieBoostToggleOffset;
			valueOffset = vehicleControlLayout.WheelieBoostValueOffset;
		}
		else if (flag25)
		{
			name = "Drift Kick";
			toggleOffset = vehicleControlLayout.DriftKickToggleOffset;
			valueOffset = vehicleControlLayout.DriftKickValueOffset;
		}
		else if (flag26)
		{
			name = "Hover Glide";
			toggleOffset = vehicleControlLayout.HoverGlideToggleOffset;
			valueOffset = vehicleControlLayout.HoverGlideValueOffset;
		}
		else if (flag27)
		{
			name = "Air Brake";
			toggleOffset = vehicleControlLayout.AirBrakeToggleOffset;
			valueOffset = vehicleControlLayout.AirBrakeValueOffset;
		}
		else if (flag28)
		{
			name = "Corner Stabilizer";
			toggleOffset = vehicleControlLayout.CornerStabilizerToggleOffset;
			valueOffset = vehicleControlLayout.CornerStabilizerValueOffset;
		}
		else if (flag29)
		{
			name = "Planted Boost";
			toggleOffset = vehicleControlLayout.PlantedBoostToggleOffset;
			valueOffset = vehicleControlLayout.PlantedBoostValueOffset;
		}
		else if (flag30)
		{
			name = "Forward Launch";
			toggleOffset = vehicleControlLayout.ForwardLaunchToggleOffset;
			valueOffset = vehicleControlLayout.ForwardLaunchValueOffset;
		}
		else if (flag31)
		{
			name = "Straight Launch";
			toggleOffset = vehicleControlLayout.StraightLaunchToggleOffset;
			valueOffset = vehicleControlLayout.StraightLaunchValueOffset;
		}
		else if (flag32)
		{
			name = "Drag Launch Assist";
			toggleOffset = vehicleControlLayout.DragLaunchAssistToggleOffset;
			valueOffset = vehicleControlLayout.DragLaunchAssistValueOffset;
		}
		else if (flag33)
		{
			name = "Tire Bite";
			toggleOffset = vehicleControlLayout.TireBiteToggleOffset;
			valueOffset = vehicleControlLayout.TireBiteValueOffset;
		}
		else if (flag34)
		{
			name = "Grip Lock";
			toggleOffset = vehicleControlLayout.GripLockToggleOffset;
			valueOffset = vehicleControlLayout.GripLockValueOffset;
		}
		else if (flag35)
		{
			name = "Forward Grip";
			toggleOffset = vehicleControlLayout.ForwardGripToggleOffset;
			valueOffset = vehicleControlLayout.ForwardGripValueOffset;
		}
		else if (flag36)
		{
			name = "Rail Grip";
			toggleOffset = vehicleControlLayout.RailGripToggleOffset;
			valueOffset = vehicleControlLayout.RailGripValueOffset;
		}
		else if (flag37)
		{
			name = "High Speed Stabilizer";
			toggleOffset = vehicleControlLayout.HighSpeedStabilizerToggleOffset;
			valueOffset = vehicleControlLayout.HighSpeedStabilizerValueOffset;
		}
		else if (flag38)
		{
			name = "Ground Clamp";
			toggleOffset = vehicleControlLayout.GroundClampToggleOffset;
			valueOffset = vehicleControlLayout.GroundClampValueOffset;
		}
		else if (flag39)
		{
			name = "Stability Rail";
			toggleOffset = vehicleControlLayout.StabilityRailToggleOffset;
			valueOffset = vehicleControlLayout.StabilityRailValueOffset;
		}
		else if (flag40)
		{
			name = "Air Control";
			toggleOffset = vehicleControlLayout.AirControlToggleOffset;
			valueOffset = vehicleControlLayout.AirControlValueOffset;
		}
		else if (flag41)
		{
			name = "Corner Bite";
			toggleOffset = vehicleControlLayout.CornerBiteToggleOffset;
			valueOffset = vehicleControlLayout.CornerBiteValueOffset;
		}
		else if (flag42)
		{
			name = "Spin Recovery";
			toggleOffset = vehicleControlLayout.SpinRecoveryToggleOffset;
			valueOffset = vehicleControlLayout.SpinRecoveryValueOffset;
		}
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "VehicleControls";
		runtimeProfileHookDescriptor.Name = name;
		runtimeProfileHookDescriptor.Signature = "F3 0F 10 4F 24 49 8B ? 0F 28 ? F3 0F 5C ? ? ? ? ? F3 0F 10";
		runtimeProfileHookDescriptor.MatchOffset = 0;
		runtimeProfileHookDescriptor.HookSize = 5;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[5] { 243, 15, 16, 79, 36 };
		runtimeProfileHookDescriptor.ToggleOffset = toggleOffset;
		runtimeProfileHookDescriptor.ValueOffset = valueOffset;
		runtimeProfileHookDescriptor.MinimumSize = vehicleControlLayout.MinimumSize;
		runtimeProfileHookDescriptor.Asm = vehicleControlLayout.Asm;
		return runtimeProfileHookDescriptor;
	}

	private static VehicleControlHookLayout GetVehicleControlLayout()
	{
		return VehicleControlLayout;
	}

	private static VehicleControlHookLayout BuildVehicleControlLayout()
	{
		List<byte> code = new List<byte>();
		Dictionary<string, int> labels = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		List<ProfileAsmFixup> fixups = new List<ProfileAsmFixup>();
		List<ProfileAsmFixup> fixups2 = new List<ProfileAsmFixup>();
		Action<string> action = delegate(string label)
		{
			labels[label] = code.Count;
		};
		EmitRipStoreRdi(code, fixups2, "vehiclePointer");
		EmitRipCmpByteImm(code, fixups2, "teleportToggle", 1);
		EmitJne(code, fixups, "teleportDone");
		EmitRipLoadXmm0Vector(code, fixups2, "teleportPosition");
		code.AddRange(new byte[4] { 15, 17, 71, 80 });
		code.AddRange(new byte[3] { 15, 87, 192 });
		code.AddRange(new byte[4] { 15, 17, 71, 32 });
		EmitRipStoreByteImm(code, fixups2, "teleportToggle", 0);
		action("teleportDone");
		EmitRipCmpByteImm(code, fixups2, "speedToggle", 1);
		EmitJne(code, fixups, "speedDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "speedValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "speedValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("speedDone");
		EmitRipCmpByteImm(code, fixups2, "jumpToggle", 1);
		EmitJne(code, fixups, "jumpDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipAddXmm1(code, fixups2, "jumpValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("jumpDone");
        EmitRipCmpByteImm(code, fixups2, "boostToggle", 1);
        EmitJne(code, fixups, "boostDone");
        code.AddRange(new byte[3] { 15, 87, 192 });
        code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
        code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
        EmitRipSubXmm0(code, fixups2, "boostValue");
        code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
        action("boostDone");
        EmitRipCmpByteImm(code, fixups2, "driftModeToggle", 1);
		EmitJne(code, fixups, "driftModeDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipAddXmm0(code, fixups2, "driftModeValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipSubXmm0(code, fixups2, "driftModeValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("driftModeDone");
		EmitRipCmpByteImm(code, fixups2, "gravityToggle", 1);
		EmitJne(code, fixups, "gravityDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipSubXmm1(code, fixups2, "gravityValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("gravityDone");
		EmitRipCmpByteImm(code, fixups2, "stabilizerToggle", 1);
		EmitJne(code, fixups, "stabilizerDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "stabilizerValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("stabilizerDone");
		EmitRipCmpByteImm(code, fixups2, "handlingToggle", 1);
		EmitJne(code, fixups, "handlingDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipSubXmm1(code, fixups2, "handlingValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("handlingDone");
		EmitRipCmpByteImm(code, fixups2, "slideToggle", 1);
		EmitJne(code, fixups, "slideDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "slideValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "slideValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("slideDone");
		EmitRipCmpByteImm(code, fixups2, "roadMagnetToggle", 1);
		EmitJne(code, fixups, "roadMagnetDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipSubXmm1(code, fixups2, "roadMagnetValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("roadMagnetDone");
		EmitRipCmpByteImm(code, fixups2, "speedTamerToggle", 1);
		EmitJne(code, fixups, "speedTamerDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "speedTamerValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "speedTamerValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("speedTamerDone");
		EmitRipCmpByteImm(code, fixups2, "airLiftToggle", 1);
		EmitJne(code, fixups, "airLiftDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipAddXmm1(code, fixups2, "airLiftValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("airLiftDone");
		EmitRipCmpByteImm(code, fixups2, "bounceCushionToggle", 1);
		EmitJne(code, fixups, "bounceCushionDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "bounceCushionValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("bounceCushionDone");
		EmitRipCmpByteImm(code, fixups2, "momentumToggle", 1);
		EmitJne(code, fixups, "momentumDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "momentumValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "momentumValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "momentumValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("momentumDone");
		EmitRipCmpByteImm(code, fixups2, "leftRightToggle", 1);
		EmitJne(code, fixups, "leftRightDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "leftRightValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		action("leftRightDone");
		EmitRipCmpByteImm(code, fixups2, "forwardBackToggle", 1);
		EmitJne(code, fixups, "forwardBackDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "forwardBackValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("forwardBackDone");
		EmitRipCmpByteImm(code, fixups2, "sidePushToggle", 1);
		EmitJne(code, fixups, "sidePushDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipAddXmm0(code, fixups2, "sidePushValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		action("sidePushDone");
		EmitRipCmpByteImm(code, fixups2, "forwardPushToggle", 1);
		EmitJne(code, fixups, "forwardPushDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipAddXmm0(code, fixups2, "forwardPushValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("forwardPushDone");
		EmitRipCmpByteImm(code, fixups2, "verticalTrimToggle", 1);
		EmitJne(code, fixups, "verticalTrimDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipAddXmm1(code, fixups2, "verticalTrimValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("verticalTrimDone");
		EmitRipCmpByteImm(code, fixups2, "sideLockToggle", 1);
		EmitJne(code, fixups, "sideLockDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "sideLockValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		action("sideLockDone");
		EmitRipCmpByteImm(code, fixups2, "forwardLockToggle", 1);
		EmitJne(code, fixups, "forwardLockDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "forwardLockValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("forwardLockDone");
		EmitRipCmpByteImm(code, fixups2, "verticalHoldToggle", 1);
		EmitJne(code, fixups, "verticalHoldDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "verticalHoldValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("verticalHoldDone");
		EmitRipCmpByteImm(code, fixups2, "motionFreezeToggle", 1);
		EmitJne(code, fixups, "motionFreezeDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "motionFreezeValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "motionFreezeValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "motionFreezeValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("motionFreezeDone");
		EmitRipCmpByteImm(code, fixups2, "wheelieBoostToggle", 1);
		EmitJne(code, fixups, "wheelieBoostDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipAddXmm0(code, fixups2, "wheelieBoostValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipAddXmm1(code, fixups2, "wheelieBoostValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("wheelieBoostDone");
		EmitRipCmpByteImm(code, fixups2, "driftKickToggle", 1);
		EmitJne(code, fixups, "driftKickDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipAddXmm0(code, fixups2, "driftKickValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipAddXmm0(code, fixups2, "driftKickValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("driftKickDone");
		EmitRipCmpByteImm(code, fixups2, "hoverGlideToggle", 1);
		EmitJne(code, fixups, "hoverGlideDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "hoverGlideValue");
		EmitRipAddXmm1(code, fixups2, "hoverGlideValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("hoverGlideDone");
		EmitRipCmpByteImm(code, fixups2, "airBrakeToggle", 1);
		EmitJne(code, fixups, "airBrakeDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "airBrakeValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "airBrakeValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "airBrakeValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("airBrakeDone");
		EmitRipCmpByteImm(code, fixups2, "cornerStabilizerToggle", 1);
		EmitJne(code, fixups, "cornerStabilizerDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "cornerStabilizerValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "cornerStabilizerValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("cornerStabilizerDone");
		EmitRipCmpByteImm(code, fixups2, "plantedBoostToggle", 1);
		EmitJne(code, fixups, "plantedBoostDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipAddXmm0(code, fixups2, "plantedBoostValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipSubXmm1(code, fixups2, "plantedBoostValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("plantedBoostDone");
		EmitRipCmpByteImm(code, fixups2, "forwardLaunchToggle", 1);
		EmitJne(code, fixups, "forwardLaunchDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipAddXmm0(code, fixups2, "forwardLaunchValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("forwardLaunchDone");
		EmitRipCmpByteImm(code, fixups2, "straightLaunchToggle", 1);
		EmitJne(code, fixups, "straightLaunchDone");
		code.AddRange(new byte[3] { 15, 87, 192 });
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipSubXmm0(code, fixups2, "straightLaunchValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("straightLaunchDone");
		EmitRipCmpByteImm(code, fixups2, "dragLaunchAssistToggle", 1);
		EmitJne(code, fixups, "dragLaunchAssistDone");
		code.AddRange(new byte[3] { 15, 87, 192 });
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipSubXmm0(code, fixups2, "dragLaunchAssistValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipSubXmm1(code, fixups2, "dragLaunchAssistValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("dragLaunchAssistDone");
		EmitRipCmpByteImm(code, fixups2, "tireBiteToggle", 1);
		EmitJne(code, fixups, "tireBiteDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "tireBiteValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		action("tireBiteDone");
		EmitRipCmpByteImm(code, fixups2, "gripLockToggle", 1);
		EmitJne(code, fixups, "gripLockDone");
		code.AddRange(new byte[3] { 15, 87, 192 });
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipSubXmm1(code, fixups2, "gripLockValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("gripLockDone");
		EmitRipCmpByteImm(code, fixups2, "forwardGripToggle", 1);
		EmitJne(code, fixups, "forwardGripDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "forwardGripValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("forwardGripDone");
		EmitRipCmpByteImm(code, fixups2, "railGripToggle", 1);
		EmitJne(code, fixups, "railGripDone");
		code.AddRange(new byte[3] { 15, 87, 192 });
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "railGripValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("railGripDone");
		EmitRipCmpByteImm(code, fixups2, "highSpeedStabilizerToggle", 1);
		EmitJne(code, fixups, "highSpeedStabilizerDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "highSpeedStabilizerValue");
		EmitRipMulXmm0(code, fixups2, "highSpeedStabilizerValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "highSpeedStabilizerValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("highSpeedStabilizerDone");
		EmitRipCmpByteImm(code, fixups2, "groundClampToggle", 1);
		EmitJne(code, fixups, "groundClampDone");
		code.AddRange(new byte[3] { 15, 87, 201 });
		EmitRipSubXmm1(code, fixups2, "groundClampValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("groundClampDone");
		EmitRipCmpByteImm(code, fixups2, "stabilityRailToggle", 1);
		EmitJne(code, fixups, "stabilityRailDone");
		code.AddRange(new byte[3] { 15, 87, 192 });
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "stabilityRailValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("stabilityRailDone");
		EmitRipCmpByteImm(code, fixups2, "airControlToggle", 1);
		EmitJne(code, fixups, "airControlDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitRipMulXmm0(code, fixups2, "airControlValue");
		EmitRipAddXmm0(code, fixups2, "airControlForwardValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipMulXmm1(code, fixups2, "airControlValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		EmitRipMulXmm0(code, fixups2, "airControlValue");
		EmitRipAddXmm0(code, fixups2, "airControlSideValue");
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("airControlDone");
		EmitRipCmpByteImm(code, fixups2, "cornerBiteToggle", 1);
		EmitJne(code, fixups, "cornerBiteDone");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		EmitOneMinusRipValueIntoXmm1(code, fixups2, "cornerBiteValue");
		code.AddRange(new byte[4] { 243, 15, 89, 193 });
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		EmitRipSubXmm1(code, fixups2, "cornerBiteValue");
		code.AddRange(new byte[5] { 243, 15, 17, 79, 36 });
		action("cornerBiteDone");
		EmitRipCmpByteImm(code, fixups2, "spinRecoveryToggle", 1);
		EmitJne(code, fixups, "spinRecoveryDone");
		EmitOneMinusRipValueIntoXmm1(code, fixups2, "spinRecoveryValue");
		code.AddRange(new byte[5] { 243, 15, 16, 71, 32 });
		code.AddRange(new byte[4] { 243, 15, 89, 193 });
		code.AddRange(new byte[5] { 243, 15, 17, 71, 32 });
		code.AddRange(new byte[5] { 243, 15, 16, 71, 40 });
		code.AddRange(new byte[4] { 243, 15, 89, 193 });
		code.AddRange(new byte[5] { 243, 15, 17, 71, 40 });
		action("spinRecoveryDone");
		code.AddRange(new byte[5] { 243, 15, 16, 79, 36 });
		int num = Align4(code.Count + 5);
		int num2 = num;
		num += 8;
		int num3 = num++;
		num = Align8(num);
		int num4 = num;
		num += 16;
		int num5 = num++;
		num = Align4(num);
		int num6 = num;
		num += 4;
		int num7 = num++;
		num = Align4(num);
		int num8 = num;
		num += 4;
		int num9 = num++;
		num = Align4(num);
		int num10 = num;
		num += 4;
		int num11 = num++;
		num = Align4(num);
		int num12 = num;
		num += 4;
		int num13 = num++;
		num = Align4(num);
		int num14 = num;
		num += 4;
		int num15 = num++;
		num = Align4(num);
		int num16 = num;
		num += 4;
		int num17 = num++;
		num = Align4(num);
		int num18 = num;
		num += 4;
		int num19 = num++;
		num = Align4(num);
		int num20 = num;
		num += 4;
		int num21 = num++;
		num = Align4(num);
		int num22 = num;
		num += 4;
		int num23 = num++;
		num = Align4(num);
		int num24 = num;
		num += 4;
		int num25 = num++;
		num = Align4(num);
		int num26 = num;
		num += 4;
		int num27 = num++;
		num = Align4(num);
		int num28 = num;
		num += 4;
		int num29 = num++;
		num = Align4(num);
		int num30 = num;
		num += 4;
		int num31 = num++;
		num = Align4(num);
		int num32 = num;
		num += 4;
		int num33 = num++;
		num = Align4(num);
		int num34 = num;
		num += 4;
		int num35 = num++;
		num = Align4(num);
		int num36 = num;
		num += 4;
		int num37 = num++;
		num = Align4(num);
		int num38 = num;
		num += 4;
		int num39 = num++;
		num = Align4(num);
		int num40 = num;
		num += 4;
		int num41 = num++;
		num = Align4(num);
		int num42 = num;
		num += 4;
		int num43 = num++;
		num = Align4(num);
		int num44 = num;
		num += 4;
		int num45 = num++;
		num = Align4(num);
		int num46 = num;
		num += 4;
		int num47 = num++;
		num = Align4(num);
		int num48 = num;
		num += 4;
		int num49 = num++;
		num = Align4(num);
		int num50 = num;
		num += 4;
		int num51 = num++;
		num = Align4(num);
		int num52 = num;
		num += 4;
		int num53 = num++;
		num = Align4(num);
		int num54 = num;
		num += 4;
		int num55 = num++;
		num = Align4(num);
		int num56 = num;
		num += 4;
		int num57 = num++;
		num = Align4(num);
		int num58 = num;
		num += 4;
		int num59 = num++;
		num = Align4(num);
		int num60 = num;
		num += 4;
		int num61 = num++;
		num = Align4(num);
		int num62 = num;
		num += 4;
		int num63 = num++;
		num = Align4(num);
		int num64 = num;
		num += 4;
		int num65 = num++;
		num = Align4(num);
		int num66 = num;
		num += 4;
		int num67 = num++;
		num = Align4(num);
		int num68 = num;
		num += 4;
		int num69 = num++;
		num = Align4(num);
		int num70 = num;
		num += 4;
		int num71 = num++;
		num = Align4(num);
		int num72 = num;
		num += 4;
		int num73 = num++;
		num = Align4(num);
		int num74 = num;
		num += 4;
		int num75 = num++;
		num = Align4(num);
		int num76 = num;
		num += 4;
		int num77 = num++;
		num = Align4(num);
		int num78 = num;
		num += 4;
		int num79 = num++;
		num = Align4(num);
		int num80 = num;
		num += 4;
		int num81 = num++;
		num = Align4(num);
		int num82 = num;
		num += 4;
		int num83 = num;
		num += 4;
		int num84 = num;
		num += 4;
		int num85 = num++;
		num = Align4(num);
		int num86 = num;
		num += 4;
		int num87 = num++;
		num = Align4(num);
		int num88 = num;
		num += 4;
		Dictionary<string, int> dictionary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
		dictionary.Add("vehiclePointer", num2);
		dictionary.Add("teleportToggle", num3);
		dictionary.Add("teleportPosition", num4);
		dictionary.Add("speedToggle", num5);
		dictionary.Add("speedValue", num6);
		dictionary.Add("jumpToggle", num7);
		dictionary.Add("jumpValue", num8);
		dictionary.Add("boostToggle", num9);
		dictionary.Add("boostValue", num10);
		dictionary.Add("driftModeToggle", num11);
		dictionary.Add("driftModeValue", num12);
		dictionary.Add("gravityToggle", num13);
		dictionary.Add("gravityValue", num14);
		dictionary.Add("stabilizerToggle", num15);
		dictionary.Add("stabilizerValue", num16);
		dictionary.Add("handlingToggle", num17);
		dictionary.Add("handlingValue", num18);
		dictionary.Add("slideToggle", num19);
		dictionary.Add("slideValue", num20);
		dictionary.Add("roadMagnetToggle", num21);
		dictionary.Add("roadMagnetValue", num22);
		dictionary.Add("speedTamerToggle", num23);
		dictionary.Add("speedTamerValue", num24);
		dictionary.Add("airLiftToggle", num25);
		dictionary.Add("airLiftValue", num26);
		dictionary.Add("bounceCushionToggle", num27);
		dictionary.Add("bounceCushionValue", num28);
		dictionary.Add("momentumToggle", num29);
		dictionary.Add("momentumValue", num30);
		dictionary.Add("leftRightToggle", num31);
		dictionary.Add("leftRightValue", num32);
		dictionary.Add("forwardBackToggle", num33);
		dictionary.Add("forwardBackValue", num34);
		dictionary.Add("sidePushToggle", num35);
		dictionary.Add("sidePushValue", num36);
		dictionary.Add("forwardPushToggle", num37);
		dictionary.Add("forwardPushValue", num38);
		dictionary.Add("verticalTrimToggle", num39);
		dictionary.Add("verticalTrimValue", num40);
		dictionary.Add("sideLockToggle", num41);
		dictionary.Add("sideLockValue", num42);
		dictionary.Add("forwardLockToggle", num43);
		dictionary.Add("forwardLockValue", num44);
		dictionary.Add("verticalHoldToggle", num45);
		dictionary.Add("verticalHoldValue", num46);
		dictionary.Add("motionFreezeToggle", num47);
		dictionary.Add("motionFreezeValue", num48);
		dictionary.Add("wheelieBoostToggle", num49);
		dictionary.Add("wheelieBoostValue", num50);
		dictionary.Add("driftKickToggle", num51);
		dictionary.Add("driftKickValue", num52);
		dictionary.Add("hoverGlideToggle", num53);
		dictionary.Add("hoverGlideValue", num54);
		dictionary.Add("airBrakeToggle", num55);
		dictionary.Add("airBrakeValue", num56);
		dictionary.Add("cornerStabilizerToggle", num57);
		dictionary.Add("cornerStabilizerValue", num58);
		dictionary.Add("plantedBoostToggle", num59);
		dictionary.Add("plantedBoostValue", num60);
		dictionary.Add("forwardLaunchToggle", num61);
		dictionary.Add("forwardLaunchValue", num62);
		dictionary.Add("straightLaunchToggle", num63);
		dictionary.Add("straightLaunchValue", num64);
		dictionary.Add("dragLaunchAssistToggle", num65);
		dictionary.Add("dragLaunchAssistValue", num66);
		dictionary.Add("tireBiteToggle", num67);
		dictionary.Add("tireBiteValue", num68);
		dictionary.Add("gripLockToggle", num69);
		dictionary.Add("gripLockValue", num70);
		dictionary.Add("forwardGripToggle", num71);
		dictionary.Add("forwardGripValue", num72);
		dictionary.Add("railGripToggle", num73);
		dictionary.Add("railGripValue", num74);
		dictionary.Add("highSpeedStabilizerToggle", num75);
		dictionary.Add("highSpeedStabilizerValue", num76);
		dictionary.Add("groundClampToggle", num77);
		dictionary.Add("groundClampValue", num78);
		dictionary.Add("stabilityRailToggle", num79);
		dictionary.Add("stabilityRailValue", num80);
		dictionary.Add("airControlToggle", num81);
		dictionary.Add("airControlValue", num82);
		dictionary.Add("airControlSideValue", num83);
		dictionary.Add("airControlForwardValue", num84);
		dictionary.Add("cornerBiteToggle", num85);
		dictionary.Add("cornerBiteValue", num86);
		dictionary.Add("spinRecoveryToggle", num87);
		dictionary.Add("spinRecoveryValue", num88);
		Dictionary<string, int> labels2 = dictionary;
		PatchRelativeFixups(code, fixups, labels);
		PatchRelativeFixups(code, fixups2, labels2);
		VehicleControlHookLayout vehicleControlHookLayout = new VehicleControlHookLayout();
		vehicleControlHookLayout.Asm = code.ToArray();
		vehicleControlHookLayout.VehiclePointerOffset = num2;
		vehicleControlHookLayout.TeleportToggleOffset = num3;
		vehicleControlHookLayout.TeleportPositionOffset = num4;
		vehicleControlHookLayout.SpeedToggleOffset = num5;
		vehicleControlHookLayout.SpeedValueOffset = num6;
		vehicleControlHookLayout.JumpToggleOffset = num7;
		vehicleControlHookLayout.JumpValueOffset = num8;
		vehicleControlHookLayout.BoostToggleOffset = num9;
		vehicleControlHookLayout.BoostValueOffset = num10;
		vehicleControlHookLayout.DriftModeToggleOffset = num11;
		vehicleControlHookLayout.DriftModeValueOffset = num12;
		vehicleControlHookLayout.GravityToggleOffset = num13;
		vehicleControlHookLayout.GravityValueOffset = num14;
		vehicleControlHookLayout.StabilizerToggleOffset = num15;
		vehicleControlHookLayout.StabilizerValueOffset = num16;
		vehicleControlHookLayout.HandlingToggleOffset = num17;
		vehicleControlHookLayout.HandlingValueOffset = num18;
		vehicleControlHookLayout.SlideToggleOffset = num19;
		vehicleControlHookLayout.SlideValueOffset = num20;
		vehicleControlHookLayout.RoadMagnetToggleOffset = num21;
		vehicleControlHookLayout.RoadMagnetValueOffset = num22;
		vehicleControlHookLayout.SpeedTamerToggleOffset = num23;
		vehicleControlHookLayout.SpeedTamerValueOffset = num24;
		vehicleControlHookLayout.AirLiftToggleOffset = num25;
		vehicleControlHookLayout.AirLiftValueOffset = num26;
		vehicleControlHookLayout.BounceCushionToggleOffset = num27;
		vehicleControlHookLayout.BounceCushionValueOffset = num28;
		vehicleControlHookLayout.MomentumToggleOffset = num29;
		vehicleControlHookLayout.MomentumValueOffset = num30;
		vehicleControlHookLayout.LeftRightToggleOffset = num31;
		vehicleControlHookLayout.LeftRightValueOffset = num32;
		vehicleControlHookLayout.ForwardBackToggleOffset = num33;
		vehicleControlHookLayout.ForwardBackValueOffset = num34;
		vehicleControlHookLayout.SidePushToggleOffset = num35;
		vehicleControlHookLayout.SidePushValueOffset = num36;
		vehicleControlHookLayout.ForwardPushToggleOffset = num37;
		vehicleControlHookLayout.ForwardPushValueOffset = num38;
		vehicleControlHookLayout.VerticalTrimToggleOffset = num39;
		vehicleControlHookLayout.VerticalTrimValueOffset = num40;
		vehicleControlHookLayout.SideLockToggleOffset = num41;
		vehicleControlHookLayout.SideLockValueOffset = num42;
		vehicleControlHookLayout.ForwardLockToggleOffset = num43;
		vehicleControlHookLayout.ForwardLockValueOffset = num44;
		vehicleControlHookLayout.VerticalHoldToggleOffset = num45;
		vehicleControlHookLayout.VerticalHoldValueOffset = num46;
		vehicleControlHookLayout.MotionFreezeToggleOffset = num47;
		vehicleControlHookLayout.MotionFreezeValueOffset = num48;
		vehicleControlHookLayout.WheelieBoostToggleOffset = num49;
		vehicleControlHookLayout.WheelieBoostValueOffset = num50;
		vehicleControlHookLayout.DriftKickToggleOffset = num51;
		vehicleControlHookLayout.DriftKickValueOffset = num52;
		vehicleControlHookLayout.HoverGlideToggleOffset = num53;
		vehicleControlHookLayout.HoverGlideValueOffset = num54;
		vehicleControlHookLayout.AirBrakeToggleOffset = num55;
		vehicleControlHookLayout.AirBrakeValueOffset = num56;
		vehicleControlHookLayout.CornerStabilizerToggleOffset = num57;
		vehicleControlHookLayout.CornerStabilizerValueOffset = num58;
		vehicleControlHookLayout.PlantedBoostToggleOffset = num59;
		vehicleControlHookLayout.PlantedBoostValueOffset = num60;
		vehicleControlHookLayout.ForwardLaunchToggleOffset = num61;
		vehicleControlHookLayout.ForwardLaunchValueOffset = num62;
		vehicleControlHookLayout.StraightLaunchToggleOffset = num63;
		vehicleControlHookLayout.StraightLaunchValueOffset = num64;
		vehicleControlHookLayout.DragLaunchAssistToggleOffset = num65;
		vehicleControlHookLayout.DragLaunchAssistValueOffset = num66;
		vehicleControlHookLayout.TireBiteToggleOffset = num67;
		vehicleControlHookLayout.TireBiteValueOffset = num68;
		vehicleControlHookLayout.GripLockToggleOffset = num69;
		vehicleControlHookLayout.GripLockValueOffset = num70;
		vehicleControlHookLayout.ForwardGripToggleOffset = num71;
		vehicleControlHookLayout.ForwardGripValueOffset = num72;
		vehicleControlHookLayout.RailGripToggleOffset = num73;
		vehicleControlHookLayout.RailGripValueOffset = num74;
		vehicleControlHookLayout.HighSpeedStabilizerToggleOffset = num75;
		vehicleControlHookLayout.HighSpeedStabilizerValueOffset = num76;
		vehicleControlHookLayout.GroundClampToggleOffset = num77;
		vehicleControlHookLayout.GroundClampValueOffset = num78;
		vehicleControlHookLayout.StabilityRailToggleOffset = num79;
		vehicleControlHookLayout.StabilityRailValueOffset = num80;
		vehicleControlHookLayout.AirControlToggleOffset = num81;
		vehicleControlHookLayout.AirControlValueOffset = num82;
		vehicleControlHookLayout.AirControlSideValueOffset = num83;
		vehicleControlHookLayout.AirControlForwardValueOffset = num84;
		vehicleControlHookLayout.CornerBiteToggleOffset = num85;
		vehicleControlHookLayout.CornerBiteValueOffset = num86;
		vehicleControlHookLayout.SpinRecoveryToggleOffset = num87;
		vehicleControlHookLayout.SpinRecoveryValueOffset = num88;
		vehicleControlHookLayout.MinimumSize = num;
		return vehicleControlHookLayout;
	}

	private static RuntimeProfileHookDescriptor GetSkillTreePerksCostDescriptor()
	{
		RuntimeProfileHookDescriptor runtimeProfileHookDescriptor = new RuntimeProfileHookDescriptor();
		runtimeProfileHookDescriptor.Key = "SkillTreePerksCost";
		runtimeProfileHookDescriptor.Name = "Skill Tree Perk Cost";
		runtimeProfileHookDescriptor.Signature = "48 89 5C 24 08 57 48 83 EC 20 48 8B 79 20 33 D2 48 8B 4F 30 E8 ? ? ? ? 48 8B 4F 30 33 D2 8B 5F 28 E8 ? ? ? ? 8B C3";
		runtimeProfileHookDescriptor.MatchOffset = 29;
		runtimeProfileHookDescriptor.HookSize = 5;
		runtimeProfileHookDescriptor.ExpectedOriginal = new byte[5] { 51, 210, 139, 95, 40 };
		runtimeProfileHookDescriptor.ToggleOffset = 26;
		runtimeProfileHookDescriptor.ValueOffset = 27;
		runtimeProfileHookDescriptor.MinimumSize = 36;
		runtimeProfileHookDescriptor.Asm = new byte[21]
		{
			49, 210, 139, 95, 40, 128, 61, 14, 0, 0,
			0, 1, 117, 7, 72, 139, 29, 6, 0, 0,
			0
		};
		return runtimeProfileHookDescriptor;
	}

	private void EnsureCrcBypass()
	{
		if (!_crcBypassActive)
		{
			if (_mainBase == 0L || _mainSize <= 0)
			{
				throw new InvalidOperationException("Main module was not captured during attach.");
			}
			byte[] array = ReadBytes(_mainBase, _mainSize);
			if (array.Length == 0)
			{
				throw new InvalidOperationException("Could not read main module memory for CRC bypass.");
			}
			int num = FindFirstExecutablePatternOffset(array, "C3");
			if (num < 0)
			{
				throw new InvalidOperationException("CRC bypass ret stub was not found.");
			}
			int num2 = FindFirstPatternOffset(array, "48 8B D9 48 8D 05 ? ? ? ? 48 89 01 E8 ? ? ? ? 48 8B CB 48 83 C4 20 5B E9");
			if (num2 < 0)
			{
				throw new InvalidOperationException("CRC bypass signature was not found. Signature: 48 8B D9 48 8D 05 ? ? ? ? 48 89 01 E8 ? ? ? ? 48 8B CB 48 83 C4 20 5B E9");
			}
			ulong num3 = _mainBase + (ulong)num2;
			ulong num4 = num3 + 3L;
			int num5 = method_1(num4 + 3L);
			ulong num6 = num4 + 7L + (ulong)num5;
			ulong num7 = num6 + 48L;
			ulong num8 = method_0(num7);
			if (num8 == 0L)
			{
				throw new InvalidOperationException("CRC bypass function pointer could not be read.");
			}
			ulong num9 = _mainBase + (ulong)num;
			method_3(num7, num9);
			_crcFunctionPointerAddress = num7;
			_crcOriginalPointer = num8;
			_crcRetAddress = num9;
			_crcBypassActive = true;
			StartCrcTimer();
			_log("CRC check bypass armed. pointer=0x" + num7.ToString("X") + ", ret=0x" + num9.ToString("X"));
		}
	}

	private RuntimeDetour CreateRuntimeDetour(RuntimeProfileHookDescriptor descriptor, ulong hookAddress)
	{
		byte[] array = ReadBytes(hookAddress, descriptor.HookSize);
		if (array.Length < descriptor.HookSize)
		{
			throw new InvalidOperationException("Could not capture original bytes for " + descriptor.Name + ".");
		}
		int num = Math.Max(descriptor.ToggleOffset + 1, (descriptor.ValueOffset >= 0) ? (descriptor.ValueOffset + 4) : 0);
		if (descriptor.CaptureOffset >= 0)
		{
			num = Math.Max(num, descriptor.CaptureOffset + 4);
		}
		if (descriptor.ObjectPointerOffset >= 0)
		{
			num = Math.Max(num, descriptor.ObjectPointerOffset + 8);
		}
		if (descriptor.MinimumSize > 0)
		{
			num = Math.Max(num, descriptor.MinimumSize);
		}
		int num2 = Math.Max(descriptor.Asm.Length + 5, num);
		ulong num3 = AllocateNear(hookAddress, num2);
		byte[] array2 = new byte[num2];
		Buffer.BlockCopy(descriptor.Asm, 0, array2, 0, descriptor.Asm.Length);
		ulong to = hookAddress + (ulong)descriptor.HookSize;
		if (descriptor.OriginalIsRelativeJump)
		{
			if (array.Length < 5 || array[0] != 233)
			{
				throw new InvalidOperationException(descriptor.Name + " original target is not a relative jump.");
			}
			int num4 = BitConverter.ToInt32(array, 1);
			to = hookAddress + 5L + (ulong)num4;
		}
		byte[] array3 = BuildRelativeJump(num3 + (ulong)descriptor.Asm.Length, to, 5);
		Buffer.BlockCopy(array3, 0, array2, descriptor.Asm.Length, array3.Length);
		WriteBytes(num3, array2);
		byte[] array4 = BuildRelativeJump(hookAddress, num3, descriptor.HookSize);
		WriteProtectedBytes(hookAddress, array4);
		RuntimeDetour runtimeDetour = new RuntimeDetour();
		runtimeDetour.Name = descriptor.Name;
		runtimeDetour.Address = hookAddress;
		runtimeDetour.DetourAddress = num3;
		runtimeDetour.Size = num2;
		runtimeDetour.Original = array;
		runtimeDetour.Patch = array4;
		return runtimeDetour;
	}

	private ulong AllocateNear(ulong target, int size)
	{
		ulong num = target & 0xFFFFFFFFFFFF0000uL;
		ulong num2 = 0uL;
		ulong num5;
		while (true)
		{
			if (num2 <= 1879048192L)
			{
				if (num > num2)
				{
					ulong address = num - num2;
					ulong num3 = TryAllocateAt(address, size, target);
					if (num3 != 0L)
					{
						return num3;
					}
				}
				ulong num4 = num + num2;
				if (num4 < 140737488289792L)
				{
					num5 = TryAllocateAt(num4, size, target);
					if (num5 != 0L)
					{
						break;
					}
				}
				num2 += 65536L;
				continue;
			}
			throw new InvalidOperationException("Could not allocate executable detour memory close enough to 0x" + target.ToString("X") + ".");
		}
		return num5;
	}

	private ulong TryAllocateAt(ulong address, int size, ulong target)
	{
		if (address == 0L)
		{
			return 0uL;
		}
		IntPtr intPtr = Native.VirtualAllocEx(_handle, new IntPtr((long)address), (UIntPtr)(ulong)Math.Max(size, 4096), 12288u, 64u);
		if (intPtr == IntPtr.Zero)
		{
			return 0uL;
		}
		ulong num = (ulong)intPtr.ToInt64();
		if (RelativeJumpFits(target, num) && RelativeJumpFits(num, target))
		{
			return num;
		}
		Native.VirtualFreeEx(_handle, intPtr, UIntPtr.Zero, 32768u);
		return 0uL;
	}

	private void StartCrcTimer()
	{
		if (_crcTimer == null)
		{
			_crcTimer = new System.Threading.Timer(CrcTimerTick, null, 10000, 10000);
		}
	}

	private void CrcTimerTick(object state)
	{
		if (Interlocked.Exchange(ref _crcTimerRunning, 1) == 1)
		{
			return;
		}
		try
		{
			lock (_runtimePatchLock)
			{
				if (!_crcBypassActive || _handle == IntPtr.Zero)
				{
					return;
				}
				foreach (RuntimeDetour value in _runtimeProfileHooks.Values)
				{
					WriteProtectedBytes(value.Address, value.Original);
				}
				RestoreValueEncryptionBypassForCleanWindow();
				method_3(_crcFunctionPointerAddress, _crcOriginalPointer);
			}
			Thread.Sleep(1000);
			lock (_runtimePatchLock)
			{
				if (!_crcBypassActive || _handle == IntPtr.Zero)
				{
					return;
				}
				method_3(_crcFunctionPointerAddress, _crcRetAddress);
				ReapplyValueEncryptionBypassForCleanWindow();
				foreach (RuntimeDetour value2 in _runtimeProfileHooks.Values)
				{
					WriteProtectedBytes(value2.Address, value2.Patch);
				}
			}
		}
		catch (Exception ex)
		{
			_log("CRC refresh failed: " + ex.Message);
		}
		finally
		{
			Interlocked.Exchange(ref _crcTimerRunning, 0);
		}
	}

	private void StopCrcTimer()
	{
		System.Threading.Timer crcTimer = _crcTimer;
		_crcTimer = null;
		crcTimer?.Dispose();
	}

	private void RestoreRuntimeProfileHooks()
	{
		StopSuperBrakeGuard();
		StopJumpGuard();
		StopBoostGuard();
		StopDriftModeGuard();
		StopAirControlGuard();
		StopTeleportToWaypointGuard();
		StopNoClipGuard();
		lock (_runtimePatchLock)
		{
			foreach (RuntimeDetour value in _runtimeProfileHooks.Values)
			{
				try
				{
					WriteProtectedBytes(value.Address, value.Original);
					if (value.DetourAddress != 0L)
					{
						Native.VirtualFreeEx(_handle, new IntPtr((long)value.DetourAddress), UIntPtr.Zero, 32768u);
					}
				}
				catch (Exception ex)
				{
					_log("Could not restore " + value.Name + " runtime hook: " + ex.Message);
				}
			}
			if (_runtimeProfileHooks.Count > 0)
			{
				_log("Restored profile runtime hooks: " + _runtimeProfileHooks.Count + ".");
			}
			_runtimeProfileHooks.Clear();
		}
	}

	private void RestoreCrcPointer()
	{
		if (!_crcBypassActive || _crcFunctionPointerAddress == 0L || _crcOriginalPointer == 0L)
		{
			return;
		}
		try
		{
			method_3(_crcFunctionPointerAddress, _crcOriginalPointer);
			_log("CRC check bypass restored.");
		}
		catch (Exception ex)
		{
			_log("Could not restore CRC bypass pointer: " + ex.Message);
		}
		finally
		{
			_crcBypassActive = false;
			_crcFunctionPointerAddress = 0uL;
			_crcOriginalPointer = 0uL;
			_crcRetAddress = 0uL;
		}
	}

	private int FindFirstPatternOffset(byte[] module, string signature)
	{
		int[] pattern = Pattern.Parse(signature);
		using (IEnumerator<int> enumerator = Pattern.FindAll(module, pattern, 1).GetEnumerator())
		{
			if (enumerator.MoveNext())
			{
				return enumerator.Current;
			}
		}
		return -1;
	}

	private static int FindAsciiOffset(byte[] module, string text)
	{
		byte[] bytes = Encoding.ASCII.GetBytes(text);
		if (bytes.Length != 0 && module.Length >= bytes.Length)
		{
			int num = module.Length - bytes.Length;
			int num2 = 0;
			while (true)
			{
				if (num2 <= num)
				{
					bool flag = true;
					for (int i = 0; i < bytes.Length; i++)
					{
						if (module[num2 + i] != bytes[i])
						{
							flag = false;
							break;
						}
					}
					if (flag)
					{
						break;
					}
					num2++;
					continue;
				}
				return -1;
			}
			return num2;
		}
		return -1;
	}

	private int FindFirstExecutablePatternOffset(byte[] module, string signature)
	{
		int[] pattern = Pattern.Parse(signature);
		foreach (int item in Pattern.FindAll(module, pattern, 512))
		{
			if (IsExecutableAddress(_mainBase + (ulong)item))
			{
				return item;
			}
		}
		return -1;
	}

	private static byte[] BuildRelativeJump(ulong from, ulong to, int length)
	{
		if (length < 5)
		{
			throw new InvalidOperationException("Relative jump patch length must be at least five bytes.");
		}
		long num = (long)(to - (from + 5L));
		if (num >= -2147483648L && num <= 2147483647L)
		{
			byte[] array = new byte[length];
			array[0] = 233;
			Buffer.BlockCopy(BitConverter.GetBytes((int)num), 0, array, 1, 4);
			for (int i = 5; i < array.Length; i++)
			{
				array[i] = 144;
			}
			return array;
		}
		throw new InvalidOperationException("Relative jump target is out of range.");
	}

	private static bool RelativeJumpFits(ulong from, ulong to)
	{
		long num = (long)(to - (from + 5L));
		if (num >= -2147483648L)
		{
			return num <= 2147483647L;
		}
		return false;
	}

	private static bool BytesStartWith(byte[] current, byte[] expected)
	{
		if (expected != null && expected.Length != 0)
		{
			if (current != null && current.Length >= expected.Length)
			{
				int num = 0;
				while (true)
				{
					if (num < expected.Length)
					{
						if (current[num] != expected[num])
						{
							break;
						}
						num++;
						continue;
					}
					return true;
				}
				return false;
			}
			return false;
		}
		return true;
	}

	private static string FormatBytes(byte[] bytes)
	{
		if (bytes != null && bytes.Length != 0)
		{
			return string.Join(" ", (from b in bytes.Take(16)
				select b.ToString("X2")).ToArray());
		}
		return string.Empty;
	}

	public void VerifyFh6Schema()
	{
		try
		{
			long? value = QueryScalarLong("SELECT count(*) FROM sqlite_master");
			long? value2 = QueryScalarLong("SELECT count(*) FROM sqlite_master WHERE type='table' AND tbl_name='Data_Car'");
			long? value3 = QueryScalarLong("SELECT count(*) FROM sqlite_master WHERE type='table' AND tbl_name='CarBuckets'");
			long? value4 = QueryScalarLong("SELECT count(*) FROM sqlite_master WHERE type='table' AND tbl_name='Data_Car_Buckets'");
			_log("SQL verified. sqlite_master entries=" + FormatNullable(value) + ", Data_Car=" + FormatNullable(value2) + ", CarBuckets=" + FormatNullable(value3) + ", Data_Car_Buckets=" + FormatNullable(value4) + ".");
		}
		catch (Exception ex)
		{
			_log("WARNING: SQL schema verification failed: " + ex.Message);
		}
	}

	public string ResolveBucketTable()
	{
		long? num = QueryScalarLong("SELECT count(*) FROM sqlite_master WHERE type='table' AND tbl_name='Data_Car_Buckets'");
		if (num.HasValue && num.Value > 0L && ColumnExists("Data_Car_Buckets", "CarId") && ColumnExists("Data_Car_Buckets", "CarBucket") && ColumnExists("Data_Car_Buckets", "BucketHero"))
		{
			return "Data_Car_Buckets";
		}
		long? num2 = QueryScalarLong("SELECT count(*) FROM sqlite_master WHERE type='table' AND tbl_name='CarBuckets'");
		if (!num2.HasValue || num2.Value <= 0L || !ColumnExists("CarBuckets", "CarId") || !ColumnExists("CarBuckets", "CarBucket") || !ColumnExists("CarBuckets", "BucketHero"))
		{
			throw new InvalidOperationException("Could not find the car-to-bucket mapping table. Expected Data_Car_Buckets with CarId/CarBucket/BucketHero.");
		}
		return "CarBuckets";
	}

	public bool TableExists(string tableName)
	{
		string text = tableName.Replace("'", "''");
		long? num = QueryScalarLong("SELECT count(*) FROM sqlite_master WHERE type='table' AND tbl_name='" + text + "'");
		if (num.HasValue)
		{
			return num.Value > 0L;
		}
		return false;
	}

	public bool ObjectExists(string objectName)
	{
		string text = objectName.Replace("'", "''");
		long? num = QueryScalarLong("SELECT count(*) FROM sqlite_master WHERE tbl_name='" + text + "' OR name='" + text + "'");
		if (num.HasValue)
		{
			return num.Value > 0L;
		}
		return false;
	}

	public bool ColumnExists(string tableName, string columnName)
	{
		try
		{
			QueryResult queryResult = Query("PRAGMA table_info(" + EscapeIdentifier(tableName) + ")");
			foreach (List<object> row in queryResult.Rows)
			{
				if (row.Count > 1 && string.Equals(Convert.ToString(row[1]), columnName, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
		}
		catch
		{
		}
		return false;
	}

	public string DumpSchemaReport(string outDir)
	{
		Directory.CreateDirectory(outDir);
		string text = DateTime.Now.ToString("yyyyMMdd_HHmmss");
		string text2 = Path.Combine(outDir, "fh6_autoshow_unlocker_schema_" + text + ".txt");
		QueryResult queryResult = Query("SELECT tbl_name, sql FROM sqlite_master WHERE type='table' ORDER BY tbl_name");
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.AppendLine("Forza Horizon 6 Luna schema report");
		stringBuilder.AppendLine("Generated: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
		stringBuilder.AppendLine("Database object: 0x" + DatabaseObject.ToString("X"));
		stringBuilder.AppendLine("ExecuteQuery: 0x" + QueryFunction.ToString("X"));
		stringBuilder.AppendLine();
		foreach (List<object> row in queryResult.Rows)
		{
			if (row.Count >= 2)
			{
				string text3 = Convert.ToString(row[0]);
				string value = Convert.ToString(row[1]);
				stringBuilder.AppendLine("[" + text3 + "]");
				stringBuilder.AppendLine(value);
				try
				{
					long? value2 = QueryScalarLong("SELECT count(*) FROM " + EscapeIdentifier(text3));
					stringBuilder.AppendLine("rows=" + FormatNullable(value2));
				}
				catch
				{
					stringBuilder.AppendLine("rows=?");
				}
				stringBuilder.AppendLine();
			}
		}
		File.WriteAllText(text2, stringBuilder.ToString(), Encoding.UTF8);
		return text2;
	}

	private static string EscapeIdentifier(string name)
	{
		return "[" + name.Replace("]", "]]") + "]";
	}

	public int PatchAutoshowRuntimeQueries()
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		if (_mainBase != 0L && _mainSize > 0)
		{
			byte[] array = ReadBytes(_mainBase, _mainSize);
			if (array.Length == 0)
			{
				throw new InvalidOperationException("Could not read main module for Autoshow query patching.");
			}
			int num = 0;
			num = 0 + PatchAscii(array, "CanBuyNewCar(Garage.Id, Garage.NotAvailableInAutoshow)", "CanBuyNewCar(Garage.Id, 0)");
			num += PatchAscii(array, "CanBuyNewCar(Id, NotAvailableInAutoshow)", "CanBuyNewCar(Id, 0)");
			num += PatchAscii(array, "Garage.NotAvailableInAutoshow", "0");
			num += PatchAscii(array, "Data_Car.NotAvailableInAutoshow", "0");
			num += PatchAscii(array, "ContentOffers.Visible AS Visible", "1 AS Visible");
			num += PatchAscii(array, "(CO.Visible = 1 OR CO.IsPurchased = 1)", "(1=1)");
			num += PatchAscii(array, "(ContentOffers.Visible='1' OR ContentOffers.IsPurchased='1')", "(1=1)");
			num += PatchAscii(array, "(Visible=1 OR IsPurchased=1)", "(1=1)");
			num += PatchAscii(array, "IsCarVisibleAndReleased(Garage.ModelId)", "1");
			num += PatchAscii(array, "IsCarVisibleAndReleased(Id)", "1");
			num += PatchAscii(array, "IsCarVisibleAndReleased(Drivable_Data_Car.Id)", "1");
			num += PatchAscii(array, "IsCarVisibleAndReleased(CAST(ContentOffersMapping.ContentId AS int))", "1");
			num += PatchAscii(array, "IsCarVisible(dc.Id)", "1");
			num += PatchAscii(array, "IsCarInstalled(Drivable_Data_Car.Id)", "1");
			num += PatchAscii(array, "IsCarInstalledAndPurchased(Garage.CarId)", "1");
			num += PatchAscii(array, "IsCarInstalledAndPurchased(CarId)", "1");
			num += PatchAscii(array, "IsCarInstalled(id)", "1");
			num += PatchAscii(array, "IsCarInstalled(Id)", "1");
			num += PatchAscii(array, "IsCarInstalled(%d)", "1");
			num += PatchAscii(array, "(VisibleOnlyIfOwned=0 OR IsOwned=1)", "(1=1)");
			num += PatchAscii(array, "(VisibleOnlyIfOwned=0)", "(1=1)");
			num += PatchAscii(array, "COM.ReleaseDateUTC <> ''", "1=1");
			num += PatchAscii(array, "SELECT 0,0,0,Data_Car.Id   FROM Data_Car", "SELECT 0,0,1,Data_Car.Id   FROM Data_Car");
			num += PatchAscii(array, "WHERE (Data_Car.VisibleOnlyIfOwned=1 AND CareerGarage.CarId IS NULL);", "WHERE (0=1);");
			num += PatchAscii(array, "Data_Car.VisibleOnlyIfOwned=1", "0=1");
			num += PatchAscii(array, "Garage.Id NOT IN (SELECT ContentId FROM Temp_InvisibleCars) AND (", "1=1 AND (");
			num += PatchAscii(array, "AND UnobtainableCars.Ordinal IS NULL", "AND 1=1");
			num += PatchAscii(array, "CREATE VIEW Drivable_Data_Car AS SELECT Data_Car.* FROM Data_Car WHERE Id NOT IN (SELECT Ordinal FROM UnobtainableCars)", "CREATE VIEW Drivable_Data_Car AS SELECT Data_Car.* FROM Data_Car");
			_log("FH6 runtime Autoshow query patches applied: " + num + ".");
			return num;
		}
		throw new InvalidOperationException("Main module was not captured during attach.");
	}

	private int PatchAscii(byte[] module, string needle, string replacement)
	{
		byte[] needleBytes = Encoding.ASCII.GetBytes(needle);
		if (needleBytes.Length == 0)
		{
			return 0;
		}
		byte[] data = BuildSqlTextReplacement(needle, replacement);
		int num = 0;
		foreach (int item in Pattern.FindBytes(module, needleBytes, 128))
		{
			ulong address = _mainBase + (ulong)item;
			if (!_memoryPatches.Any((MemoryPatch p) => RangesOverlap(address, needleBytes.Length, p.Address, p.Original.Length)))
			{
				byte[] array = ReadBytes(address, needleBytes.Length);
				if (array.Length == needleBytes.Length)
				{
					WriteProtectedBytes(address, data);
					_memoryPatches.Add(new MemoryPatch
					{
						Address = address,
						Original = array
					});
					num++;
					_log("Patched Autoshow query text at 0x" + address.ToString("X") + ": " + Truncate(needle, 90) + " -> " + Truncate(replacement, 90));
				}
			}
		}
		return num;
	}

	private static bool RangesOverlap(ulong firstAddress, int firstLength, ulong secondAddress, int secondLength)
	{
		ulong num = firstAddress + (ulong)Math.Max(firstLength, 0);
		ulong num2 = secondAddress + (ulong)Math.Max(secondLength, 0);
		if (firstAddress < num2)
		{
			return secondAddress < num;
		}
		return false;
	}

	private static byte[] BuildSqlTextReplacement(string original, string replacement)
	{
		if (replacement.Length > original.Length)
		{
			throw new InvalidOperationException("Replacement is longer than the Autoshow query fragment.");
		}
		string text = replacement;
		if (original.EndsWith(";", StringComparison.Ordinal) && !replacement.EndsWith(";", StringComparison.Ordinal))
		{
			text = replacement + ";";
		}
		if (text.Length > original.Length)
		{
			throw new InvalidOperationException("Replacement is longer than the Autoshow query fragment.");
		}
		if (original.EndsWith(";", StringComparison.Ordinal) && text.EndsWith(";", StringComparison.Ordinal))
		{
			string text2 = text.Substring(0, text.Length - 1);
			text = text2 + new string(' ', original.Length - text2.Length - 1) + ";";
		}
		else
		{
			text += new string(' ', original.Length - text.Length);
		}
		return Encoding.ASCII.GetBytes(text);
	}

	private DatabaseCandidate TryBuildCandidate(byte[] moduleBytes, ulong moduleBase, int matchOffset)
	{
		for (int i = 0; i < 24 && matchOffset + i + 7 < moduleBytes.Length; i++)
		{
			if (moduleBytes[matchOffset + i] != 72 || moduleBytes[matchOffset + i + 1] != 139 || (moduleBytes[matchOffset + i + 2] != 53 && moduleBytes[matchOffset + i + 2] != 13))
			{
				continue;
			}
			int num = BitConverter.ToInt32(moduleBytes, matchOffset + i + 3);
			long num2 = (long)moduleBase + (long)matchOffset + i + 7L;
			ulong num3 = (ulong)(num2 + num);
			ulong num4 = method_0(num3);
			if (num4 == 0L)
			{
				continue;
			}
			ulong num5 = method_0(num4);
			if (num5 != 0L)
			{
				ulong num6 = method_0(num5 + 72L);
				if (num6 != 0L && IsExecutableAddress(num6))
				{
					return new DatabaseCandidate
					{
						Valid = true,
						MatchAddress = moduleBase + (ulong)matchOffset,
						PointerAddress = num3,
						DatabaseObject = num4,
						QueryFunction = num6
					};
				}
			}
		}
		return default(DatabaseCandidate);
	}

	private bool IsExecutableAddress(ulong address)
	{
		UIntPtr dwLength = (UIntPtr)(ulong)Marshal.SizeOf(typeof(Native.MemoryBasicInformation64));
		Native.MemoryBasicInformation64 lpBuffer;
		UIntPtr uIntPtr = Native.VirtualQueryEx(_handle, new UIntPtr(address), out lpBuffer, dwLength);
		if (uIntPtr != UIntPtr.Zero && lpBuffer.State == 4096)
		{
			return Native.IsExecutable(lpBuffer.Protect);
		}
		return false;
	}

	public void Execute(string sql)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		DatabaseCandidate candidate = ((_candidates.Count == 0) ? new DatabaseCandidate
		{
			Valid = true,
			DatabaseObject = DatabaseObject,
			QueryFunction = QueryFunction
		} : _candidates[0]);
		ExecuteOnCandidate(sql, candidate);
		_log("SQL executed on FH6 CDatabase db=0x" + candidate.DatabaseObject.ToString("X") + ": " + Truncate(sql, 140));
	}

	public QueryResult Query(string sql)
	{
		if (!IsAlive)
		{
			throw new InvalidOperationException("Not attached.");
		}
		DatabaseCandidate candidate = ((_candidates.Count == 0) ? new DatabaseCandidate
		{
			Valid = true,
			DatabaseObject = DatabaseObject,
			QueryFunction = QueryFunction
		} : _candidates[0]);
		ulong num = ExecuteOnCandidate(sql, candidate);
		QueryResult result = ((num == 0L) ? new QueryResult() : ParseQueryResult(num));
		_log("SQL query executed on FH6 CDatabase db=0x" + candidate.DatabaseObject.ToString("X") + ": " + Truncate(sql, 140));
		return result;
	}

	public long? QueryScalarLong(string sql)
	{
		QueryResult queryResult = Query(sql);
		if (queryResult.Rows.Count != 0 && queryResult.Rows[0].Count != 0)
		{
			object obj = queryResult.Rows[0][0];
			if (obj == null)
			{
				return null;
			}
			if (obj is long)
			{
				return (long)obj;
			}
			if (obj is int)
			{
				return (int)obj;
			}
			if (obj is double)
			{
				return (long)(double)obj;
			}
			if (long.TryParse(Convert.ToString(obj), out var result))
			{
				return result;
			}
			return null;
		}
		return null;
	}

	private ulong ExecuteOnCandidate(string sql, DatabaseCandidate candidate)
	{
		byte[] bytes = Encoding.ASCII.GetBytes(sql + "\0");
		IntPtr intPtr = Native.VirtualAllocEx(_handle, IntPtr.Zero, (UIntPtr)(ulong)Math.Max(4096, bytes.Length), 12288u, 4u);
		IntPtr intPtr2 = Native.VirtualAllocEx(_handle, IntPtr.Zero, (UIntPtr)8u, 12288u, 4u);
		IntPtr intPtr3 = Native.VirtualAllocEx(_handle, IntPtr.Zero, (UIntPtr)4096u, 12288u, 64u);
		if (!(intPtr == IntPtr.Zero) && !(intPtr2 == IntPtr.Zero) && !(intPtr3 == IntPtr.Zero))
		{
			try
			{
				WriteBytes((ulong)intPtr.ToInt64(), bytes);
				WriteBytes((ulong)intPtr2.ToInt64(), new byte[8]);
				byte[] data = BuildQueryShellcode((ulong)intPtr2.ToInt64(), (ulong)intPtr.ToInt64(), candidate.QueryFunction);
				WriteBytes((ulong)intPtr3.ToInt64(), data);
				uint lpThreadId;
				IntPtr intPtr4 = Native.CreateRemoteThread(_handle, IntPtr.Zero, 0u, intPtr3, new IntPtr((long)candidate.DatabaseObject), 0u, out lpThreadId);
				if (intPtr4 == IntPtr.Zero)
				{
					throw new InvalidOperationException("CreateRemoteThread failed.");
				}
				uint num = Native.WaitForSingleObject(intPtr4, 15000u);
				Native.GetExitCodeThread(intPtr4, out var lpExitCode);
				Native.CloseHandle(intPtr4);
				if (num == 258)
				{
					throw new InvalidOperationException("Remote SQL thread timed out.");
				}
				if (lpExitCode != 0)
				{
					_log("SQL candidate exit 0x" + lpExitCode.ToString("X") + " db=0x" + candidate.DatabaseObject.ToString("X"));
				}
				return method_0((ulong)intPtr2.ToInt64());
			}
			finally
			{
				if (intPtr3 != IntPtr.Zero)
				{
					Native.VirtualFreeEx(_handle, intPtr3, UIntPtr.Zero, 32768u);
				}
				if (intPtr != IntPtr.Zero)
				{
					Native.VirtualFreeEx(_handle, intPtr, UIntPtr.Zero, 32768u);
				}
				if (intPtr2 != IntPtr.Zero)
				{
					Native.VirtualFreeEx(_handle, intPtr2, UIntPtr.Zero, 32768u);
				}
			}
		}
		throw new InvalidOperationException("VirtualAllocEx failed.");
	}

	private QueryResult ParseQueryResult(ulong resultPtr)
	{
		QueryResult queryResult = new QueryResult();
		byte[] array = ReadBytes(resultPtr, 72);
		if (array.Length < 72)
		{
			return queryResult;
		}
		ulong num = BitConverter.ToUInt64(array, 8);
		ulong num2 = BitConverter.ToUInt64(array, 16);
		ulong num3 = BitConverter.ToUInt64(array, 32);
		ulong num4 = BitConverter.ToUInt64(array, 40);
		if (num != 0L && num2 >= num)
		{
			ulong num5 = num2 - num;
			int num6 = (int)(num5 / 40L);
			if (num6 > 0 && num6 <= 1000)
			{
				byte[] array2 = ReadBytes(num, (int)num5);
				if (array2.Length < (int)num5)
				{
					return queryResult;
				}
				for (int i = 0; i < num6; i++)
				{
					int num7 = i * 40;
					string text = ReadMsvcString(num + (ulong)num7);
					queryResult.Columns.Add(text ?? "?");
				}
				if (num3 != 0L && num4 >= num3)
				{
					ulong num8 = num4 - num3;
					int num9 = (int)(num8 / 8L);
					if (num9 > 0 && num9 <= 100000)
					{
						byte[] array3 = ReadBytes(num3, num9 * 8);
						if (array3.Length < num9 * 8)
						{
							return queryResult;
						}
						for (int j = 0; j < num9; j++)
						{
							ulong num10 = BitConverter.ToUInt64(array3, j * 8);
							List<object> list = new List<object>();
							if (num10 == 0L)
							{
								for (int k = 0; k < num6; k++)
								{
									list.Add(null);
								}
								queryResult.Rows.Add(list);
								continue;
							}
							byte[] array4 = ReadBytes(num10, num6 * 16);
							if (array4.Length < num6 * 16)
							{
								for (int l = 0; l < num6; l++)
								{
									list.Add(null);
								}
								queryResult.Rows.Add(list);
								continue;
							}
							for (int m = 0; m < num6; m++)
							{
								int num11 = m * 16;
								switch (array4[num11])
								{
								case 2:
									list.Add(BitConverter.ToInt64(array4, num11 + 8));
									break;
								case 3:
									list.Add(BitConverter.ToDouble(array4, num11 + 8));
									break;
								case 4:
								{
									ulong address = BitConverter.ToUInt64(array4, num11 + 8);
									list.Add(ReadMsvcString(address) ?? "");
									break;
								}
								default:
									list.Add(null);
									break;
								}
							}
							queryResult.Rows.Add(list);
						}
						return queryResult;
					}
					return queryResult;
				}
				return queryResult;
			}
			return queryResult;
		}
		return queryResult;
	}

	private string ReadMsvcString(ulong address)
	{
		if (address == 0L)
		{
			return null;
		}
		byte[] array = ReadBytes(address, 32);
		if (array.Length < 32)
		{
			return null;
		}
		ulong num = BitConverter.ToUInt64(array, 16);
		ulong num2 = BitConverter.ToUInt64(array, 24);
		if (num == 0L)
		{
			return "";
		}
		if (num > 1048576L)
		{
			return null;
		}
		if (num2 <= 15L)
		{
			int count = (int)Math.Min(num, 15uL);
			return Encoding.ASCII.GetString(array, 0, count);
		}
		ulong num3 = BitConverter.ToUInt64(array, 0);
		if (num3 == 0L)
		{
			return null;
		}
		byte[] array2 = ReadBytes(num3, (int)num);
		if (array2.Length < (int)num)
		{
			return null;
		}
		return Encoding.ASCII.GetString(array2);
	}

	private static string FormatNullable(long? value)
	{
		if (!value.HasValue)
		{
			return "?";
		}
		return value.Value.ToString();
	}

	private static byte[] BuildQueryShellcode(ulong resultPtr, ulong sqlPtr, ulong functionPtr)
	{
		byte[] array = new byte[34]
		{
			72, 186, 0, 0, 0, 0, 0, 0, 0, 0,
			73, 184, 0, 0, 0, 0, 0, 0, 0, 0,
			255, 37, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0
		};
		Buffer.BlockCopy(BitConverter.GetBytes(resultPtr), 0, array, 2, 8);
		Buffer.BlockCopy(BitConverter.GetBytes(sqlPtr), 0, array, 12, 8);
		Buffer.BlockCopy(BitConverter.GetBytes(functionPtr), 0, array, array.Length - 8, 8);
		return array;
	}

	public List<string> DumpSqliteImages(string outDir)
	{
		List<string> list = new List<string>();
		byte[] bytes = Encoding.ASCII.GetBytes("SQLite format 3\0");
		List<ulong> list2 = new List<ulong>();
		ulong num = 0uL;
		UIntPtr dwLength = (UIntPtr)(ulong)Marshal.SizeOf(typeof(Native.MemoryBasicInformation64));
		while (num < 140737488355327L)
		{
			Native.MemoryBasicInformation64 lpBuffer;
			UIntPtr uIntPtr = Native.VirtualQueryEx(_handle, new UIntPtr(num), out lpBuffer, dwLength);
			if (uIntPtr == UIntPtr.Zero)
			{
				break;
			}
			ulong baseAddress = lpBuffer.BaseAddress;
			ulong regionSize = lpBuffer.RegionSize;
			ulong num2 = baseAddress + Math.Max(regionSize, 4096uL);
			if (lpBuffer.State == 4096 && Native.IsReadable(lpBuffer.Protect) && regionSize > 0L && regionSize <= 536870912L)
			{
				try
				{
					int length = (int)Math.Min(regionSize, 67108864uL);
					byte[] data = ReadBytes(baseAddress, length);
					foreach (int item in Pattern.FindBytes(data, bytes, 4))
					{
						ulong hit = baseAddress + (ulong)item;
						if (list2.Any((ulong s) => hit >= s && hit - s < 1048576L))
						{
							continue;
						}
						list2.Add(hit);
						string text = DumpSqliteAt(hit, outDir);
						if (text != null)
						{
							list.Add(text);
							if (list.Count >= 5)
							{
								return list;
							}
						}
					}
				}
				catch
				{
				}
			}
			if (num2 <= num)
			{
				break;
			}
			num = num2;
		}
		return list;
	}

	private string DumpSqliteAt(ulong address, string outDir)
	{
		byte[] array = ReadBytes(address, 100);
		if (array.Length < 100)
		{
			return null;
		}
		int num = (array[16] << 8) | array[17];
		if (num == 1)
		{
			num = 65536;
		}
		if (num < 512 || num > 65536 || (num & (num - 1)) != 0)
		{
			num = 4096;
		}
		int num2 = smethod_0(array, 28);
		long num3 = ((num2 <= 0 || num2 >= 1000000) ? 33554432L : ((long)num * (long)num2));
		if (num3 < num)
		{
			num3 = 33554432L;
		}
		if (num3 > 268435456L)
		{
			num3 = 268435456L;
		}
		string text = DateTime.Now.ToString("yyyyMMdd_HHmmss");
		string text2 = Path.Combine(outDir, "sqlite_live_" + text + "_0x" + address.ToString("X") + ".sqlite");
		using (FileStream fileStream = File.Create(text2))
		{
			long num4 = num3;
			ulong num5 = address;
			while (num4 > 0L)
			{
				byte[] array2 = ReadBytes(num5, (int)Math.Min(1048576L, num4));
				if (array2.Length != 0)
				{
					fileStream.Write(array2, 0, array2.Length);
					num5 += (ulong)array2.Length;
					num4 -= array2.Length;
					if (array2.Length < Math.Min(1048576L, num4 + array2.Length))
					{
						break;
					}
					continue;
				}
				break;
			}
		}
		return text2;
	}

	private static int smethod_0(byte[] data, int offset)
	{
		return (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
	}

	private byte[] ReadBytes(ulong address, int length)
	{
		if (length <= 0)
		{
			return new byte[0];
		}
		byte[] array = new byte[length];
		UIntPtr lpNumberOfBytesRead;
		bool flag = Native.ReadProcessMemory(_handle, new IntPtr((long)address), array, (UIntPtr)(ulong)length, out lpNumberOfBytesRead);
		int num = (int)(uint)lpNumberOfBytesRead;
		if (flag && num > 0)
		{
			if (num == length)
			{
				return array;
			}
			byte[] array2 = new byte[num];
			Buffer.BlockCopy(array, 0, array2, 0, num);
			return array2;
		}
		return new byte[0];
	}

	private ulong method_0(ulong address)
	{
		byte[] array = ReadBytes(address, 8);
		if (array.Length < 8)
		{
			return 0uL;
		}
		return BitConverter.ToUInt64(array, 0);
	}

	private int method_1(ulong address)
	{
		byte[] array = ReadBytes(address, 4);
		if (array.Length < 4)
		{
			return 0;
		}
		return BitConverter.ToInt32(array, 0);
	}

	private float ReadFloat(ulong address)
	{
		byte[] array = ReadBytes(address, 4);
		if (array.Length < 4)
		{
			return 0f;
		}
		return BitConverter.ToSingle(array, 0);
	}

	private void WriteBytes(ulong address, byte[] data)
	{
		if (!Native.WriteProcessMemory(_handle, new IntPtr((long)address), data, (UIntPtr)(ulong)data.Length, out var lpNumberOfBytesWritten) || (ulong)lpNumberOfBytesWritten != (ulong)data.Length)
		{
			throw new InvalidOperationException("WriteProcessMemory failed.");
		}
	}

	private void WriteByte(ulong address, byte value)
	{
		WriteBytes(address, new byte[1] { value });
	}

	private void method_2(ulong address, int value)
	{
		WriteBytes(address, BitConverter.GetBytes(value));
	}

	private void WriteFloat(ulong address, float value)
	{
		WriteBytes(address, BitConverter.GetBytes(value));
	}

	private void method_3(ulong address, ulong value)
	{
		WriteProtectedBytes(address, BitConverter.GetBytes(value));
	}

	private void WriteTimeAttackBytes(ulong address, byte[] data)
	{
		if (IsWritableMemoryRange(address, data.Length))
		{
			WriteBytes(address, data);
		}
		else
		{
			WriteProtectedBytes(address, data);
		}
	}

	private bool IsWritableMemoryRange(ulong address, int length)
	{
		if (length <= 0)
		{
			return false;
		}
		UIntPtr dwLength = (UIntPtr)(ulong)Marshal.SizeOf(typeof(Native.MemoryBasicInformation64));
		Native.MemoryBasicInformation64 lpBuffer;
		UIntPtr uIntPtr = Native.VirtualQueryEx(_handle, new UIntPtr(address), out lpBuffer, dwLength);
		if (!(uIntPtr == UIntPtr.Zero) && lpBuffer.State == 4096 && IsReadableWritable(lpBuffer.Protect))
		{
			ulong num = address + (ulong)length;
			ulong num2 = lpBuffer.BaseAddress + lpBuffer.RegionSize;
			if (num >= address && address >= lpBuffer.BaseAddress)
			{
				return num <= num2;
			}
			return false;
		}
		return false;
	}

	private bool IsReadableMemoryRange(ulong address, int length)
	{
		if (length <= 0)
		{
			return false;
		}
		UIntPtr dwLength = (UIntPtr)(ulong)Marshal.SizeOf(typeof(Native.MemoryBasicInformation64));
		Native.MemoryBasicInformation64 lpBuffer;
		UIntPtr uIntPtr = Native.VirtualQueryEx(_handle, new UIntPtr(address), out lpBuffer, dwLength);
		if (!(uIntPtr == UIntPtr.Zero) && lpBuffer.State == 4096 && Native.IsReadable(lpBuffer.Protect))
		{
			ulong num = address + (ulong)length;
			ulong num2 = lpBuffer.BaseAddress + lpBuffer.RegionSize;
			if (num >= address && address >= lpBuffer.BaseAddress)
			{
				return num <= num2;
			}
			return false;
		}
		return false;
	}

	private void WriteProtectedBytes(ulong address, byte[] data)
	{
		if (!Native.VirtualProtectEx(_handle, new IntPtr((long)address), (UIntPtr)(ulong)data.Length, 64u, out var lpflOldProtect))
		{
			throw new InvalidOperationException("VirtualProtectEx failed.");
		}
		try
		{
			WriteBytes(address, data);
		}
		finally
		{
			Native.VirtualProtectEx(_handle, new IntPtr((long)address), (UIntPtr)(ulong)data.Length, lpflOldProtect, out var _);
		}
	}

	private static string Truncate(string text, int max)
	{
		if (text != null && text.Length > max)
		{
			return text.Substring(0, max) + "...";
		}
		return text;
	}

	public void Dispose()
	{
		if (_handle != IntPtr.Zero)
		{
			StopSuperBrakeGuard();
			StopJumpGuard();
			StopBoostGuard();
			StopDriftModeGuard();
			StopAirControlGuard();
			StopTeleportToWaypointGuard();
			StopNoClipGuard();
			StopXpValueGuard();
			RestoreValueEncryptionBypass();
			StopCrcTimer();
			RestoreRuntimeProfileHooks();
			RestoreFovTablePatches();
			RestoreTimeAttackInfluencePatches();
			RestoreBestWheelspinOddsPatches();
			RestoreCrcPointer();
			Native.CloseHandle(_handle);
			_handle = IntPtr.Zero;
		}
	}
}
