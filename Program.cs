using MyCrypto;

byte[] data = "Hello World!"u8.ToArray();

Console.WriteLine(Convert.ToHexString(SHA256.Hash(data)));
Console.WriteLine(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)));
Console.WriteLine(SHA256.Hash(data).AsSpan().SequenceEqual(System.Security.Cryptography.SHA256.HashData(data)));