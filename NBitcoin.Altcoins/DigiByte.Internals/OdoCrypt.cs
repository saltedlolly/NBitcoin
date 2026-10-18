// Port of DigiByte Core src/crypto/odocrypt.cpp and hashodo.h
// Copyright (c) 2009-2018 The DigiByte developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

using System;

namespace NBitcoin.Altcoins.DigiByteInternals
{
	public class OdoCrypt
	{
		// Block size, in bytes
		public const int DIGEST_SIZE = 80;

		const int ROUNDS = 84;
		const int SMALL_SBOX_WIDTH = 6;
		const int LARGE_SBOX_WIDTH = 10;
		const int PBOX_SUBROUNDS = 6;
		const int PBOX_M = 3;
		const int ROTATION_COUNT = 6;
		const int WORD_BITS = 64;
		const int DIGEST_BITS = 8 * DIGEST_SIZE;
		const int STATE_SIZE = DIGEST_BITS / WORD_BITS;
		const int SMALL_SBOX_COUNT = DIGEST_BITS / (SMALL_SBOX_WIDTH + LARGE_SBOX_WIDTH);
		const int LARGE_SBOX_COUNT = STATE_SIZE;

		class Pbox
		{
			public readonly ulong[][] Mask = new ulong[PBOX_SUBROUNDS][];
			public readonly int[][] Rotation = new int[PBOX_SUBROUNDS - 1][];
		}

		readonly byte[][] Sbox1 = new byte[SMALL_SBOX_COUNT][];
		readonly ushort[][] Sbox2 = new ushort[LARGE_SBOX_COUNT][];
		readonly Pbox[] Permutation = { new Pbox(), new Pbox() };
		readonly int[] Rotations = new int[ROTATION_COUNT];
		readonly ushort[] RoundKey = new ushort[ROUNDS];

		class OdoRandom
		{
			// LCG parameters from Knuth
			const ulong BASE_MULTIPLICAND = 6364136223846793005UL;
			const ulong BASE_ADDEND = 1442695040888963407UL;

			ulong current;
			ulong multiplicand = 1;
			ulong addend = 0;

			public OdoRandom(uint seed)
			{
				current = seed;
			}

			// Gives the 1st, 3rd, 6th, 10th, etc output of a standard LCG, so every
			// seed produces a unique sequence.
			public uint NextInt()
			{
				unchecked
				{
					addend += multiplicand * BASE_ADDEND;
					multiplicand *= BASE_MULTIPLICAND;
					current = current * multiplicand + addend;
				}
				return (uint)(current >> 32);
			}

			public ulong NextLong()
			{
				ulong hi = NextInt();
				return (hi << 32) | NextInt();
			}

			public int Next(int n)
			{
				return (int)(((ulong)NextInt() * (ulong)n) >> 32);
			}

			public int[] Permutation(int size)
			{
				var arr = new int[size];
				for (int i = 0; i < size; i++)
					arr[i] = i;
				for (int i = 1; i < size; i++)
				{
					int j = Next(i + 1);
					(arr[i], arr[j]) = (arr[j], arr[i]);
				}
				return arr;
			}
		}

		public OdoCrypt(uint key)
		{
			var r = new OdoRandom(key);

			// Randomize each s-box
			for (int i = 0; i < SMALL_SBOX_COUNT; i++)
				Sbox1[i] = Array.ConvertAll(r.Permutation(1 << SMALL_SBOX_WIDTH), v => (byte)v);
			for (int i = 0; i < LARGE_SBOX_COUNT; i++)
				Sbox2[i] = Array.ConvertAll(r.Permutation(1 << LARGE_SBOX_WIDTH), v => (ushort)v);

			// Randomize each p-box
			foreach (var perm in Permutation)
			{
				for (int j = 0; j < PBOX_SUBROUNDS; j++)
				{
					perm.Mask[j] = new ulong[STATE_SIZE / 2];
					for (int k = 0; k < STATE_SIZE / 2; k++)
						perm.Mask[j][k] = r.NextLong();
				}
				for (int j = 0; j < PBOX_SUBROUNDS - 1; j++)
				{
					perm.Rotation[j] = new int[STATE_SIZE / 2];
					for (int k = 0; k < STATE_SIZE / 2; k++)
						perm.Rotation[j][k] = r.Next(63) + 1;
				}
			}

			// Randomize rotations. Rotations must be distinct, non-zero, and have odd sum
			var bits = r.Permutation(WORD_BITS - 1);
			int sum = 0;
			for (int j = 0; j < ROTATION_COUNT - 1; j++)
			{
				Rotations[j] = bits[j] + 1;
				sum += Rotations[j];
			}
			for (int j = ROTATION_COUNT - 1; ; j++)
			{
				if ((bits[j] + 1 + sum) % 2 != 0)
				{
					Rotations[ROTATION_COUNT - 1] = bits[j] + 1;
					break;
				}
			}

			// Randomize each round key
			for (int i = 0; i < ROUNDS; i++)
				RoundKey[i] = (ushort)r.Next(1 << STATE_SIZE);
		}

		public void Encrypt(byte[] cipher, byte[] plain)
		{
			var state = new ulong[STATE_SIZE];
			Unpack(state, plain);
			PreMix(state);
			for (int round = 0; round < ROUNDS; round++)
			{
				ApplyPbox(state, Permutation[0]);
				ApplySboxes(state);
				ApplyPbox(state, Permutation[1]);
				ApplyRotations(state);
				ApplyRoundKey(state, RoundKey[round]);
			}
			Pack(state, cipher);
		}

		static void Unpack(ulong[] state, byte[] bytes)
		{
			for (int i = 0; i < STATE_SIZE; i++)
			{
				state[i] = 0;
				for (int j = 0; j < 8; j++)
					state[i] |= (ulong)bytes[8 * i + j] << (8 * j);
			}
		}

		static void Pack(ulong[] state, byte[] bytes)
		{
			for (int i = 0; i < STATE_SIZE; i++)
				for (int j = 0; j < 8; j++)
					bytes[8 * i + j] = (byte)(state[i] >> (8 * j));
		}

		// Pre-mix the bits. Involution.
		static void PreMix(ulong[] state)
		{
			ulong total = 0;
			for (int i = 0; i < STATE_SIZE; i++)
				total ^= state[i];
			total ^= total >> 32;
			for (int i = 0; i < STATE_SIZE; i++)
				state[i] ^= total;
		}

		// Non-linear substitution.
		void ApplySboxes(ulong[] state)
		{
			const ulong MASK1 = (1 << SMALL_SBOX_WIDTH) - 1;
			const ulong MASK2 = (1 << LARGE_SBOX_WIDTH) - 1;

			int smallSboxIndex = 0;
			for (int i = 0; i < STATE_SIZE; i++)
			{
				ulong next = 0;
				int pos = 0;
				int largeSboxIndex = i;
				for (int j = 0; j < SMALL_SBOX_COUNT / STATE_SIZE; j++)
				{
					next |= (ulong)Sbox1[smallSboxIndex][(state[i] >> pos) & MASK1] << pos;
					pos += SMALL_SBOX_WIDTH;
					next |= (ulong)Sbox2[largeSboxIndex][(state[i] >> pos) & MASK2] << pos;
					pos += LARGE_SBOX_WIDTH;
					smallSboxIndex++;
				}
				state[i] = next;
			}
		}

		static void ApplyMaskedSwaps(ulong[] state, ulong[] mask)
		{
			for (int i = 0; i < STATE_SIZE / 2; i++)
			{
				// For each bit set in the mask, swap the corresponding bits in `a` and `b`
				ulong swp = mask[i] & (state[2 * i] ^ state[2 * i + 1]);
				state[2 * i] ^= swp;
				state[2 * i + 1] ^= swp;
			}
		}

		static void ApplyWordShuffle(ulong[] state, int m)
		{
			var next = new ulong[STATE_SIZE];
			for (int i = 0; i < STATE_SIZE; i++)
				next[m * i % STATE_SIZE] = state[i];
			Array.Copy(next, state, STATE_SIZE);
		}

		static ulong Rot(ulong x, int r)
		{
			return r == 0 ? x : (x << r) ^ (x >> (64 - r));
		}

		static void ApplyPboxRotations(ulong[] state, int[] rotation)
		{
			// Only rotate the even words
			for (int i = 0; i < STATE_SIZE / 2; i++)
				state[2 * i] = Rot(state[2 * i], rotation[i]);
		}

		// Permute the bits.
		static void ApplyPbox(ulong[] state, Pbox perm)
		{
			for (int i = 0; i < PBOX_SUBROUNDS - 1; i++)
			{
				ApplyMaskedSwaps(state, perm.Mask[i]);
				ApplyWordShuffle(state, PBOX_M);
				ApplyPboxRotations(state, perm.Rotation[i]);
			}
			ApplyMaskedSwaps(state, perm.Mask[PBOX_SUBROUNDS - 1]);
		}

		// Linear mix step.
		void ApplyRotations(ulong[] state)
		{
			var next = new ulong[STATE_SIZE];
			// std::rotate_copy(state, state+1, state+STATE_SIZE, next)
			for (int i = 0; i < STATE_SIZE; i++)
				next[i] = state[(i + 1) % STATE_SIZE];
			for (int i = 0; i < STATE_SIZE; i++)
				for (int j = 0; j < ROTATION_COUNT; j++)
					next[i] ^= Rot(state[i], Rotations[j]);
			Array.Copy(next, state, STATE_SIZE);
		}

		// Add round key. Involution.
		static void ApplyRoundKey(ulong[] state, int roundKey)
		{
			for (int i = 0; i < STATE_SIZE; i++)
				state[i] ^= (ulong)((roundKey >> i) & 1);
		}

		/// <summary>
		/// Odo PoW hash (DigiByte Core HashOdo): OdoCrypt-encrypt the 80-byte header,
		/// then apply Keccak-p[800] with 12 rounds and take the first 32 bytes.
		/// </summary>
		public static byte[] Hash(byte[] header, uint key)
		{
			return Hash(header, new OdoCrypt(key));
		}

		public static byte[] Hash(byte[] header, OdoCrypt odo)
		{
			if (header.Length > DIGEST_SIZE)
				throw new ArgumentException("Odo input is limited to 80 bytes", nameof(header));
			var cipher = new byte[KeccakP800.StateSizeInBytes];
			Array.Copy(header, cipher, header.Length);
			cipher[header.Length] = 1;
			var block = new byte[DIGEST_SIZE];
			Array.Copy(cipher, block, DIGEST_SIZE);
			odo.Encrypt(block, block);
			Array.Copy(block, cipher, DIGEST_SIZE);
			KeccakP800.Permute12Rounds(cipher);
			var hash = new byte[32];
			Array.Copy(cipher, hash, 32);
			return hash;
		}
	}

	/// <summary>
	/// Keccak-p[800] permutation (port of the Keccak Team's reference implementation, CC0).
	/// </summary>
	public static class KeccakP800
	{
		public const int StateSizeInBytes = 100;
		const int MaxNrRounds = 22;

		static readonly uint[] RoundConstants =
		{
			0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001,
			0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
			0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
			0x0000800a, 0x8000000a, 0x80008081, 0x00008080,
		};

		static readonly int[] RhoOffsets =
		{
			0, 1, 30, 28, 27, 4, 12, 6, 23, 20, 3, 10, 11, 25, 7, 9, 13, 15, 21, 8, 18, 2, 29, 24, 14
		};

		static int Index(int x, int y) => (x % 5) + 5 * (y % 5);

		static uint Rol32(uint a, int offset) => offset != 0 ? (a << offset) ^ (a >> (32 - offset)) : a;

		public static void Permute12Rounds(byte[] state)
		{
			var a = new uint[25];
			for (int i = 0; i < 25; i++)
				a[i] = (uint)(state[4 * i] | state[4 * i + 1] << 8 | state[4 * i + 2] << 16 | state[4 * i + 3] << 24);
			for (int round = MaxNrRounds - 12; round < MaxNrRounds; round++)
				Round(a, round);
			for (int i = 0; i < 25; i++)
				for (int j = 0; j < 4; j++)
					state[4 * i + j] = (byte)(a[i] >> (8 * j));
		}

		static void Round(uint[] a, int indexRound)
		{
			// theta
			var c = new uint[5];
			var d = new uint[5];
			for (int x = 0; x < 5; x++)
				for (int y = 0; y < 5; y++)
					c[x] ^= a[Index(x, y)];
			for (int x = 0; x < 5; x++)
				d[x] = Rol32(c[(x + 1) % 5], 1) ^ c[(x + 4) % 5];
			for (int x = 0; x < 5; x++)
				for (int y = 0; y < 5; y++)
					a[Index(x, y)] ^= d[x];
			// rho
			for (int i = 0; i < 25; i++)
				a[i] = Rol32(a[i], RhoOffsets[i]);
			// pi
			var temp = (uint[])a.Clone();
			for (int x = 0; x < 5; x++)
				for (int y = 0; y < 5; y++)
					a[Index(y, 2 * x + 3 * y)] = temp[Index(x, y)];
			// chi
			for (int y = 0; y < 5; y++)
			{
				for (int x = 0; x < 5; x++)
					c[x] = a[Index(x, y)] ^ (~a[Index(x + 1, y)] & a[Index(x + 2, y)]);
				for (int x = 0; x < 5; x++)
					a[Index(x, y)] = c[x];
			}
			// iota
			a[0] ^= RoundConstants[indexRound];
		}
	}
}
