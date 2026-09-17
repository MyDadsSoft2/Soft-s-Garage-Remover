using System;
using System.Collections.Generic;

namespace SoftsGarageRemover;

internal static class Pattern
{
	public static int[] Parse(string pattern)
	{
		string[] array = pattern.Split(new char[1] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
		int[] array2 = new int[array.Length];
		for (int i = 0; i < array.Length; i++)
		{
			array2[i] = ((array[i] == "?" || array[i] == "??") ? (-1) : Convert.ToInt32(array[i], 16));
		}
		return array2;
	}

	public static IEnumerable<int> FindAll(byte[] data, int[] pattern, int max)
	{
		int found = 0;
		for (int i = 0; i <= data.Length - pattern.Length; i++)
		{
			bool match = true;
			for (int j = 0; j < pattern.Length; j++)
			{
				if (pattern[j] >= 0 && data[i + j] != pattern[j])
				{
					match = false;
					break;
				}
			}
			if (match)
			{
				yield return i;
				found++;
				if (found >= max)
				{
					break;
				}
			}
		}
	}

	public static IEnumerable<int> FindBytes(byte[] data, byte[] needle, int max)
	{
		int found = 0;
		for (int i = 0; i <= data.Length - needle.Length; i++)
		{
			bool match = true;
			for (int j = 0; j < needle.Length; j++)
			{
				if (data[i + j] != needle[j])
				{
					match = false;
					break;
				}
			}
			if (match)
			{
				yield return i;
				found++;
				if (found >= max)
				{
					break;
				}
			}
		}
	}
}
