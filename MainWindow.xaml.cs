using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
// ─────────────────────────────────────────────────────────
// IMPORTANT EVERYTHING HERE IS COOKED
// Some times maybe good sometimes maybe shit
// ─────────────────────────────────────────────────────────

namespace SoftsGarageRemover
{
    public partial class MainWindow : Window
    {
        // ── State ──
        private RemoteDatabase? _db;
        private List<GarageCar> _cars = new();
        private ICollectionView? _carsView;
        private string _garageIdCol = "Id";
        private string _carFkCol = "CarId";
        private string _carNameCol = "MediaName";
        private const string GARAGE_TABLE = "Profile0_Career_Garage";
        public MainWindow()
        {
            InitializeComponent();
            CarGrid.SelectionChanged += (_, _) => UpdateSelectionText();
            Log("Ready. Attach to FH6 to get started.");
        }



        // ══════════════════════════════════════════════════════
        //  Logging
        // ══════════════════════════════════════════════════════
        private void Log(string msg)
        {
            string line = $"[{DateTime.Now:HH:mm:ss}] {msg}";
            Dispatcher.Invoke(() =>
            {
                LogBox.AppendText(line + Environment.NewLine);
                LogBox.ScrollToEnd();
            });
        }

        // ══════════════════════════════════════════════════════
        //  Connection
        // ══════════════════════════════════════════════════════
        private void SetConnected(bool attached, string? proc = null, int? pid = null)
        {
            Dispatcher.Invoke(() =>
            {
                var green = Color.FromRgb(0x00, 0xE6, 0x76);
                var red = Color.FromRgb(0xFF, 0x52, 0x52);

                StatusDot.Fill = new SolidColorBrush(attached ? green : red);
                StatusLabel.Text = attached ? $"ONLINE — {proc} (PID {pid})" : "OFFLINE";
                StatusLabel.Foreground = new SolidColorBrush(attached ? green : Color.FromRgb(0x5C, 0x5C, 0x72));
                AttachBtn.Content = attached ? "Reattach" : "Attach to FH6";
            });
        }

        private bool EnsureAttached()
        {
            if (_db != null && _db.IsAlive) return true;
            Log("Not attached — click Attach to FH6 first.");
            return false;
        }

        private void Safe(Action action)
        {
            try { action(); }
            catch (Exception ex) { Log("Error: " + ex.Message); }
        }

        // ══════════════════════════════════════════════════════
        //  Attach process *idfk*
        // ══════════════════════════════════════════════════════
        private void AttachBtn_Click(object sender, RoutedEventArgs e) => Safe(() =>
        {
            if (_db != null)
            {
                _db.RestoreMemoryPatches();
                _db.Dispose();
                _db = null;
            }
            SetConnected(false);

            Process? proc = Process.GetProcesses().FirstOrDefault(p =>
                p.ProcessName.IndexOf("ForzaHorizon6", StringComparison.OrdinalIgnoreCase) >= 0 ||
                p.ProcessName.IndexOf("FH6", StringComparison.OrdinalIgnoreCase) >= 0);

            if (proc == null)
            {
                Log("FH6 not found. Make sure the game is running.");
                MessageBox.Show("FH6 process not found.\nMake sure the game is running.",
                    "Soft's Garage Remover", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _db = new RemoteDatabase(proc, Log);
            _db.Attach();
            _db.VerifyFh6Schema();

            Log($"Attached to {proc.ProcessName} (PID {proc.Id}).");
            SetConnected(true, proc.ProcessName, proc.Id);

            // Auto-discover schema
            try
            {
                Log("══════ PROFILE0_CAREER_GARAGE ══════");

                var info = _db.Query("PRAGMA table_info(Profile0_Career_Garage)");

                Log($"Columns: {info.Rows.Count}");

                foreach (var row in info.Rows)
                {
                    Log(string.Join(" | ",
                        row.Select(x => x?.ToString() ?? "NULL")));
                }

                var sample = _db.Query("SELECT * FROM Profile0_Career_Garage LIMIT 5");

                Log($"Sample rows: {sample.Rows.Count}");

                foreach (var col in sample.Columns)
                    Log("COL: " + col);

                for (int r = 0; r < sample.Rows.Count; r++)
                {
                    Log("ROW " + r);

                    for (int c = 0; c < sample.Columns.Count; c++)
                        Log($"  {sample.Columns[c]} = {sample.Rows[r][c]}");
                }
            }
            catch (Exception ex)
            {
                Log("Profile0_Career_Garage error: " + ex.Message);
            }
        });

        // ══════════════════════════════════════════════════════
        //  Schema discovery
        //   This might have gave me cancer
        // ══════════════════════════════════════════════════════
        private void DiscoverGarageSchema()
        {
            try
            {
                Log("══════ SCHEMA DISCOVERY ══════");

                var garageInfo = _db!.Query($"PRAGMA table_info({GARAGE_TABLE})");

                Log($"Garage PRAGMA returned {garageInfo.Rows.Count} rows");

                foreach (var row in garageInfo.Rows)
                {
                    try
                    {
                        Log("Garage RAW: " +
                            string.Join(" | ",
                                row.Select(x => x?.ToString() ?? "NULL")));
                    }
                    catch { }
                }

                var carInfo = _db!.Query("PRAGMA table_info(Data_Car)");

                Log($"Data_Car PRAGMA returned {carInfo.Rows.Count} rows");

                foreach (var row in carInfo.Rows.Take(12))
                {
                    try
                    {
                        Log("Data_Car RAW: " +
                            string.Join(" | ",
                                row.Select(x => x?.ToString() ?? "NULL")));
                    }
                    catch { }
                }

                var garageCols = GetColumnNames(GARAGE_TABLE);
                var carCols = GetColumnNames("Data_Car");

                Log("Garage columns: " + string.Join(", ", garageCols));
                Log("Data_Car columns: " + string.Join(", ", carCols.Take(20)));

                _garageIdCol = garageCols.Contains("Id")
                    ? "Id"
                    : garageCols.FirstOrDefault() ?? "Id";

                if (garageCols.Contains("CarId"))
                    _carFkCol = "CarId";
                else if (garageCols.Contains("ModelId"))
                    _carFkCol = "ModelId";
                else if (garageCols.Contains("CarModelId"))
                    _carFkCol = "CarModelId";
                else
                    _carFkCol = "CarId";

                if (carCols.Contains("MediaName"))
                    _carNameCol = "MediaName";
                else if (carCols.Contains("Description"))
                    _carNameCol = "Description";
                else if (carCols.Contains("DisplayName"))
                    _carNameCol = "DisplayName";
                else
                    _carNameCol = "Id";

                Log($"Schema: PK={_garageIdCol}, FK={_carFkCol}, Name={_carNameCol}");
            }
            catch (Exception ex)
            {
                Log("Schema discovery failed: " + ex);
            }
        }

        private List<string> GetColumnNames(string table)
        {
            var result = _db!.Query($"PRAGMA table_info({table})");
            return result.Rows
                .Where(r => r.Count > 1 && r[1] != null)
                .Select(r => Convert.ToString(r[1])!)
                .ToList();
        }

        // ══════════════════════════════════════════════════════
        //  Load Garage
        // ══════════════════════════════════════════════════════
        private void LoadGarage_Click(object sender, RoutedEventArgs e) => Safe(() =>
        {
            if (!EnsureAttached()) return;
            Log("Loading garage...");

            var sql =
                $"SELECT G.{_garageIdCol} AS gid, G.{_carFkCol} AS cid, " +
                $"COALESCE(DC.{_carNameCol}, 'Car #' || G.{_carFkCol}) AS cname, " +
                $"(SELECT count(*) FROM Profile0_Career_Garage G2 WHERE G2.{_carFkCol} = G.{_carFkCol}) AS cnt " +
                $"FROM Profile0_Career_Garage G " +
                $"LEFT JOIN Data_Car DC ON DC.Id = G.{_carFkCol} " +
                $"ORDER BY cnt DESC, cname";

            RemoteDatabase.QueryResult? result = null;

            // Try the discovered schema first, then fall back
            string[] attempts = { sql,
                "SELECT G.Id AS gid, G.CarId AS cid, COALESCE(DC.MediaName, DC.Description, 'Car #'||G.CarId) AS cname, " +
                "(SELECT count(*) FROM Profile0_Career_Garage G2 WHERE G2.CarId=G.CarId) AS cnt FROM Profile0_Career_Garage G LEFT JOIN Data_Car DC ON DC.Id=G.CarId ORDER BY cnt DESC, cname",

                "SELECT G.Id AS gid, G.ModelId AS cid, COALESCE(DC.MediaName, DC.Description, 'Car #'||G.ModelId) AS cname, " +
                "(SELECT count(*) FROM Profile0_Career_Garage G2 WHERE G2.ModelId=G.ModelId) AS cnt FROM Profile0_Career_Garage G LEFT JOIN Data_Car DC ON DC.Id=G.ModelId ORDER BY cnt DESC, cname",
            };

            foreach (var attempt in attempts)
            {
                try
                {
                    Log("═══════════════════════════════");
                    Log("Trying query:");
                    Log(attempt);

                    result = _db!.Query(attempt);

                    Log($"SUCCESS: {result.Rows.Count} rows returned");
                    Log($"Columns: {string.Join(", ", result.Columns)}");

                    if (result.Rows.Count > 0)
                        break;
                }
                catch (Exception ex)
                {
                    Log("FAILED:");
                    Log(ex.Message);
                    result = null;
                }
            }

            // Parse
            int iGid = Math.Max(0, result.Columns.IndexOf("gid"));
            int iCid = Math.Max(0, result.Columns.IndexOf("cid"));
            int iName = Math.Max(0, result.Columns.IndexOf("cname"));
            int iCnt = Math.Max(0, result.Columns.IndexOf("cnt"));
            // fallback to positional
            if (result.Columns.IndexOf("gid") < 0) { iGid = 0; iCid = 1; iName = 2; iCnt = 3; }

            _cars.Clear();
            foreach (var row in result.Rows)
            {
                try
                {
                    _cars.Add(new GarageCar
                    {
                        GarageId = Convert.ToInt64(row[iGid] ?? 0),
                        CarId = Convert.ToInt64(row[iCid] ?? 0),
                        CarName = Convert.ToString(row[iName] ?? "?") ?? "?",
                        OwnedCount = Convert.ToInt32(row[iCnt] ?? 1),
                    });
                }
                catch { }
            }

            // Wrap the list in a CollectionView so we can filter it live from the
            // search box without touching the underlying _cars data or breaking
            // sort/select/dupe logic (those all still operate on _cars directly).
            _carsView = CollectionViewSource.GetDefaultView(_cars);
            _carsView.Filter = FilterCar;

            CarGrid.ItemsSource = _carsView;

            int total = _cars.Count;
            int unique = _cars.Select(c => c.CarId).Distinct().Count();
            int dupes = total - unique;

            StatsText.Text = $"{total} cars   ·   {unique} unique models   ·   {dupes} duplicates";
            Log($"Loaded {total} car(s). {unique} unique, {dupes} dupe(s).");

            // Re-apply whatever search text is already in the box (e.g. after a reload)
            _carsView.Refresh();
            UpdateStatsForFilter();
        });

        // ══════════════════════════════════════════════════════
        //  Search
        // ══════════════════════════════════════════════════════
        private bool FilterCar(object obj)
        {
            if (obj is not GarageCar car) return true;

            string? query = SearchBox?.Text?.Trim();
            if (string.IsNullOrEmpty(query)) return true;

            return car.CarName.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0
                || car.CarId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase)
                || car.GarageId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase);
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            _carsView?.Refresh();
            UpdateStatsForFilter();
        }

        private void ClearSearchBtn_Click(object sender, RoutedEventArgs e)
        {
            SearchBox.Text = "";
            SearchBox.Focus();
        }

        /// <summary>Updates the stats bar to show how many rows match the current search.</summary>
        private void UpdateStatsForFilter()
        {
            if (_cars.Count == 0) return;

            int total = _cars.Count;
            int unique = _cars.Select(c => c.CarId).Distinct().Count();
            int dupes = total - unique;

            string query = SearchBox?.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(query))
            {
                StatsText.Text = $"{total} cars   ·   {unique} unique models   ·   {dupes} duplicates";
            }
            else
            {
                int shown = _carsView?.Cast<GarageCar>().Count() ?? 0;
                StatsText.Text = $"{shown} of {total} cars match \"{query}\"   ·   {unique} unique models   ·   {dupes} duplicates";
            }
        }

        // ══════════════════════════════════════════════════════
        //  Select all duplicates
        // ══════════════════════════════════════════════════════
        private void SelectDupes_Click(object sender, RoutedEventArgs e) => Safe(() =>
        {
            if (_cars.Count == 0) { Log("Load the garage first."); return; }

            // For each CarId group, keep the first, mark the rest
            var keepIds = new HashSet<long>();
            var toSelect = new HashSet<long>();

            foreach (var group in _cars.GroupBy(c => c.CarId))
            {
                bool kept = false;
                foreach (var car in group)
                {
                    if (!kept) { keepIds.Add(car.GarageId); kept = true; }
                    else toSelect.Add(car.GarageId);
                }
            }

            CarGrid.SelectedItems.Clear();
            foreach (var car in _cars)
                if (toSelect.Contains(car.GarageId))
                    CarGrid.SelectedItems.Add(car);

            Log($"Selected {CarGrid.SelectedItems.Count} duplicate(s) — keeping 1 of each model.");
        });

        // ══════════════════════════════════════════════════════
        //  Remove selected 
        // ══════════════════════════════════════════════════════
        private void RemoveSelected_Click(object sender, RoutedEventArgs e) => Safe(() =>
        {
            if (!EnsureAttached()) return;
            var selected = CarGrid.SelectedItems.Cast<GarageCar>().ToList();
            if (selected.Count == 0) { Log("Select cars to remove first."); return; }

            var answer = MessageBox.Show(
                $"Remove {selected.Count} car(s) from your garage?\n\n" +
                "This modifies the live in-memory database.\n" +
                "To undo: force-close FH6 before it auto-saves.",
                "Confirm Removal", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes) return;

            int ok = 0, fail = 0;
            foreach (var car in selected)
            {
                try
                {
                    _db!.Execute($"DELETE FROM Profile0_Career_Garage WHERE {_garageIdCol} = {car.GarageId}");
                    ok++;
                }
                catch (Exception ex)
                {
                    fail++;
                    if (fail <= 3) Log($"  Failed {car.GarageId}: {ex.Message}");
                }
            }

            Log($"Removed {ok} car(s)." + (fail > 0 ? $" {fail} failed." : ""));

            MessageBox.Show(
                $"Done — removed {ok} car(s).\n\n" +
                "Leave the garage screen and come back to see changes.",
                "Soft's Garage Remover", MessageBoxButton.OK, MessageBoxImage.Information);

            // Refresh
            LoadGarage_Click(sender, e);
        });

        // ══════════════════════════════════════════════════════
        //  Nuke all dupes — one SQL statement
        // ══════════════════════════════════════════════════════
        private void NukeAllDupes_Click(object sender, RoutedEventArgs e) => Safe(() =>
        {
            if (!EnsureAttached()) return;

            long total = _db!.QueryScalarLong("SELECT count(*) FROM Garage") ?? 0;
            long unique = 0;

            // Try both possible FK column names
            try { unique = _db!.QueryScalarLong($"SELECT count(DISTINCT {_carFkCol}) FROM Garage") ?? 0; }
            catch
            {
                try { unique = _db!.QueryScalarLong("SELECT count(DISTINCT CarId) FROM Garage") ?? 0; }
                catch
                {
                    try { unique = _db!.QueryScalarLong("SELECT count(DISTINCT ModelId) FROM Garage") ?? 0; }
                    catch { Log("Couldn't count unique cars."); return; }
                }
            }

            long dupes = total - unique;
            if (dupes <= 0)
            {
                MessageBox.Show("No duplicates found.", "Soft's Garage Remover",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var answer = MessageBox.Show(
                $"Your garage: {total} cars, {unique} unique models.\n\n" +
                $"This will DELETE {dupes} duplicate(s), keeping the original of each.\n\n" +
                "Continue?", "Nuke All Dupes",
                MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes) return;

            // Keep the lowest Garage ID per car model, delete the rest
            string fk = _carFkCol;
            try
            {
                _db!.Execute(
                    $"DELETE FROM Garage WHERE {_garageIdCol} NOT IN " +
                    $"(SELECT MIN({_garageIdCol}) FROM Garage GROUP BY {fk})");
            }
            catch
            {
                // Fallback column names
                try
                {
                    _db!.Execute(
                        "DELETE FROM Garage WHERE Id NOT IN " +
                        "(SELECT MIN(Id) FROM Garage GROUP BY CarId)");
                }
                catch (Exception ex2)
                {
                    Log("Nuke failed: " + ex2.Message);
                    return;
                }
            }

            long after = _db!.QueryScalarLong("SELECT count(*) FROM Garage") ?? 0;
            long removed = total - after;

            Log($"Nuked {removed} dupe(s). {after} cars remain.");
            MessageBox.Show(
                $"Removed {removed} duplicate car(s).\n{after} cars remain.\n\n" +
                "Leave the garage screen and come back to see changes.",
                "Soft's Garage Remover", MessageBoxButton.OK, MessageBoxImage.Information);

            LoadGarage_Click(sender, e);
        });

        // ══════════════════════════════════════════════════════
        //  Remove one copy of each duplicate (not all of them)
        // ══════════════════════════════════════════════════════
        private void RemoveOneOfEachDupe_Click(object sender, RoutedEventArgs e) => Safe(() =>
        {
            if (!EnsureAttached()) return;
            if (_cars.Count == 0) { Log("Load the garage first."); return; }

            var dupeGroups = _cars.GroupBy(c => c.CarId).Where(g => g.Count() > 1).ToList();
            if (dupeGroups.Count == 0)
            {
                MessageBox.Show("No duplicates found.", "Soft's Garage Remover",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var answer = MessageBox.Show(
                $"This removes exactly ONE copy from each duplicated model ({dupeGroups.Count} affected),\n" +
                "leaving the rest of your dupes untouched.\n\nContinue?",
                "Remove One of Each Duplicate", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes) return;

            int ok = 0, fail = 0;
            foreach (var group in dupeGroups)
            {
                // Drop the newest copy (highest GarageId) from each stack, keep the rest.
                var toRemove = group.OrderByDescending(c => c.GarageId).First();
                try
                {
                    _db!.Execute($"DELETE FROM Profile0_Career_Garage WHERE {_garageIdCol} = {toRemove.GarageId}");
                    ok++;
                }
                catch (Exception ex)
                {
                    fail++;
                    if (fail <= 3) Log($"  Failed {toRemove.GarageId}: {ex.Message}");
                }
            }

            Log($"Removed one copy from {ok} duplicated model(s)." + (fail > 0 ? $" {fail} failed." : ""));

            MessageBox.Show(
                $"Done — removed {ok} car(s), one from each duplicate stack.\n\n" +
                "Leave the garage screen and come back to see changes.",
                "Soft's Garage Remover", MessageBoxButton.OK, MessageBoxImage.Information);

            LoadGarage_Click(sender, e);
        });

        // ══════════════════════════════════════════════════════
        //  Dump schema (debug)
        // ══════════════════════════════════════════════════════
        private void DumpSchema_Click(object sender, RoutedEventArgs e) => Safe(() =>
        {
            if (!EnsureAttached()) return;

            Log("═══ Garage Schema ═══");
            try
            {
                var info = _db!.Query("PRAGMA table_info(Garage)");
                foreach (var row in info.Rows)
                    Log($"  Garage.{Convert.ToString(row[1])}  ({Convert.ToString(row[2])})");

                var count = _db!.QueryScalarLong("SELECT count(*) FROM Garage");
                Log($"  → {count} row(s)");
            }
            catch (Exception ex) { Log("  Garage: " + ex.Message); }

            Log("═══ Data_Car Schema (first 12 cols) ═══");
            try
            {
                var info = _db!.Query("PRAGMA table_info(Data_Car)");
                int i = 0;
                foreach (var row in info.Rows)
                {
                    if (i++ >= 12) { Log("  ..."); break; }
                    Log($"  Data_Car.{Convert.ToString(row[1])}  ({Convert.ToString(row[2])})");
                }
            }
            catch (Exception ex) { Log("  Data_Car: " + ex.Message); }

            // Sample a row so the user can see what data looks like
            Log("═══ Garage Definition ═══");

            try
            {
                var def = _db!.Query(
                    "SELECT type,name,sql FROM sqlite_master WHERE name='Garage'"
                );

                foreach (var row in def.Rows)
                {
                    Log(string.Join(" | ",
                        row.Select(x => x?.ToString() ?? "NULL")));
                }
            }
            catch (Exception ex)
            {
                Log("Definition error: " + ex.Message);
            }

            Log("═══ Sample Garage Row ═══");

            try
            {
                var sample = _db!.Query("SELECT * FROM Garage LIMIT 5");

                Log($"Rows={sample.Rows.Count}");
                Log($"Cols={sample.Columns.Count}");

                foreach (var col in sample.Columns)
                    Log("COL: " + col);

                if (sample.Rows.Count > 0)
                {
                    for (int r = 0; r < sample.Rows.Count; r++)
                    {
                        Log("ROW " + r);

                        for (int c = 0; c < sample.Columns.Count; c++)
                        {
                            Log($"  {sample.Columns[c]} = {sample.Rows[r][c]}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Sample error: " + ex.Message);
            }
        });

        // ══════════════════════════════════════════════════════
        //  Helpers Works to an extent
        // ══════════════════════════════════════════════════════
        private void UpdateSelectionText()
        {
            int count = CarGrid.SelectedItems.Count;
            SelectionText.Text = count > 0 ? $"{count} selected" : "";
        }

        protected override void OnClosed(EventArgs e)
        {
            if (_db != null)
            {
                try { _db.RestoreMemoryPatches(); } catch { }
                try { _db.Dispose(); } catch { }
                _db = null;
            }
            base.OnClosed(e);
        }
    }
}
