# Soft's Garage Remover

A standalone tool for managing your Forza Horizon 6 garage — find and remove 
duplicate cars without the pain of doing it one-by-one through the game's UI.

---

## How it works

FH6 keeps your garage data in a live in-memory SQLite database while the game
runs. This tool reads that database to list your cars, spots duplicates, and 
lets you remove them with SQL DELETE — the same way the game itself would.

Changes happen in the live database. They persist when the game auto-saves. 
If you want to undo, force-close FH6 (Alt+F4 / Task Manager) before it saves.

---

## Project setup

This is a .NET 8 WPF project.

### 1. Copy your existing infrastructure files

You need these files from your VantaMenu project. Drop them into this folder:

```
SoftsGarageRemover/
├── SoftsGarageRemover.csproj
├── App.xaml
├── App.xaml.cs
├── MainWindow.xaml
├── MainWindow.xaml.cs
├── GarageCar.cs
│
│   ── Copy these from VantaMenu ──
├── RemoteDatabase.cs      ← your existing DB class
├── Native.cs              ← P/Invoke wrappers  
├── Pattern.cs             ← AOB pattern scanner
└── RuntimeProfileFeature.cs  ← enum (needed by RemoteDatabase)
```

### 2. Fix the namespace

In each copied file, either:
- Change `namespace VantaMenu` → `namespace SoftsGarageRemover`
- Or add `using VantaMenu;` at the top of `MainWindow.xaml.cs`

### 3. Build & run

```
dotnet build
dotnet run
```

Or open in Visual Studio / Rider and hit F5.

---

## Usage

1. Launch FH6 and get past the loading screen
2. Open Soft's Garage Remover
3. Click **Attach to FH6**
4. Click **Load Garage** — your full car list appears with dupe counts
5. Click **Select All Dupes** to highlight every extra copy
6. Review the selection, deselect anything you want to keep
7. Click **Remove Selected**
8. In FH6: leave the garage screen and come back — the dupes are gone

Or use **Nuke All Dupes** to remove every duplicate in one shot (keeps 1 of each model).

### Schema issues

FH6's database columns aren't publicly documented. The tool auto-discovers them 
on attach. If something doesn't work, click **Dump Schema** — it logs the exact
column names so you can see what FH6 is using in your build.

---

## Disclaimer

This tool modifies the game's live in-memory data. Use offline / in solo play.
Using any external tool in online multiplayer can risk account action from 
Playground Games. Use at your own discretion.
