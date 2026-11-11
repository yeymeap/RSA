using System.Buffers.Binary;
using System.Numerics;

namespace RSA;

public class SHA256
{
    private static readonly uint[] K = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
    private static readonly uint[] initialH = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    private uint[] state = new uint[8];

    private static uint Rotr(uint x, int n) // n is expected to be between 0 and 31
    {
        //uint result = BitOperations.RotateRight(x, n);
        //return result;
        return (x >> n) | (x << (32 - n));
    }

    private static uint Shr(uint x, int n)
    {
        return x >> n;
    }

    private static uint Ch(uint x, uint y, uint z)
    {
        return (x & y) ^ (~x & z);
    }

    private static uint Maj(uint x, uint y, uint z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static uint BigSigma0(uint x)
    {
        return Rotr(x, 2) ^ Rotr(x, 13) ^ Rotr(x, 22);
    }

    private static uint BigSigma1(uint x)
    {
        return Rotr(x, 6) ^ Rotr(x, 11) ^ Rotr(x, 25);
    }

    private static uint SmallSigma0(uint x)
    {
        return Rotr(x, 7) ^ Rotr(x, 18) ^ Shr(x, 3);
    }

    private static uint SmallSigma1(uint x)
    {
        return Rotr(x, 17) ^ Rotr(x, 19) ^ Shr(x, 10);
    }

    private static byte[] Padding(byte[] input)
    {
        int len = input.Length;
        int paddedLength = ((len + 9 + 63) / 64) * 64;
        byte[] result = new byte[paddedLength];
        Array.Copy(input, result, len);
        result[len] = 0x80;
        ulong bitLength = ((ulong)len * 8);
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(paddedLength - 8), bitLength);
        return result;
    }
    
    private static uint[] MessageSchedule(byte[] padded, int offset)
    {
        uint[] W = new uint[64];
        for (int i = 0; i < 16; i++)
        {
            W[i] = BinaryPrimitives.ReadUInt32BigEndian(padded.AsSpan(offset + i * 4));
        }
        for (int t = 16; t < 64; t++)
        {
            W[t] = SmallSigma1(W[t - 2]) + W[t - 7] + SmallSigma0(W[t - 15]) + W[t - 16];
        }
        return W;
    }

    private static void Compression(uint[] state, uint[] W)
    {
        uint a = state[0], b = state[1], c = state[2], d = state[3],  e = state[4],  f = state[5], g = state[6], h = state[7];
        for (int t = 0; t < 64; t++)
        {
            uint T1 = h + BigSigma1(e) + Ch(e, f, g) + K[t] + W[t];
            uint T2 = BigSigma0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
        
    }

    public static byte[] Hash(byte[] input)
    {
        uint[] state = (uint[])initialH.Clone();
        byte[] padded = Padding(input);
        for (int offset = 0; offset < padded.Length; offset += 64)
        {
            uint[] w = MessageSchedule(padded, offset);
            Compression(state, w);
        }

        byte[] result = new byte[32];
        for (int i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(i * 4), state[i]);
        }
        return result;
    }
}