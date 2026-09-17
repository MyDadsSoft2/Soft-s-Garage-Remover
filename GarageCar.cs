namespace SoftsGarageRemover;

/// <summary>One row in the player's garage.</summary>
public sealed class GarageCar
{
    public long GarageId { get; set; }
    public long CarId { get; set; }
    public string CarName { get; set; } = "";
    public int OwnedCount { get; set; }
    public bool IsDuplicate => OwnedCount > 1;
    public string Status => IsDuplicate ? $"DUPE  ×{OwnedCount}" : "Unique";
}
