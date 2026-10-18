using System;
using System.Linq;
using NBitcoin.Altcoins.DigiByteInternals;
using NBitcoin.Altcoins.HashX11;
using NBitcoin.Crypto;
using NBitcoin.DataEncoders;

namespace NBitcoin.Altcoins
{
    public class DigiByte : NetworkSetBase
    {
        public static DigiByte Instance { get; } = new();
        public override string CryptoCode => "DGB";

        private DigiByte() { }

#pragma warning disable CS0618 // Type or member is obsolete
        public class DigiByteConsensusFactory : ConsensusFactory
        {
            public DigiByteConsensusFactory(uint odoShapechangeInterval)
            {
                OdoShapechangeInterval = odoShapechangeInterval;
            }

            // Mainnet and regtest change the Odo key every 10 days, testnet every day
            public static DigiByteConsensusFactory Mainnet { get; } = new(10 * 24 * 60 * 60);
            public static DigiByteConsensusFactory Testnet { get; } = new(1 * 24 * 60 * 60);
            public static DigiByteConsensusFactory Regtest { get; } = new(10 * 24 * 60 * 60);

            public uint OdoShapechangeInterval { get; }

            Tuple<uint, OdoCrypt> _lastOdo;

            internal OdoCrypt GetOdoCrypt(uint time)
            {
                var key = time - time % OdoShapechangeInterval;
                var last = _lastOdo;
                if (last != null && last.Item1 == key)
                    return last.Item2;
                var odo = new OdoCrypt(key);
                _lastOdo = Tuple.Create(key, odo);
                return odo;
            }

            public override BlockHeader CreateBlockHeader()
            {
                return new DigiByteBlockHeader(this);
            }

            public override Block CreateBlock()
            {
                return new DigiByteBlock(new DigiByteBlockHeader(this));
            }
        }

        public enum DigiByteAlgo
        {
            Unknown = -1,
            SHA256D = 0,
            Scrypt = 1,
            Groestl = 2,
            Skein = 3,
            Qubit = 4,
            Odo = 7,
        }

        public class DigiByteBlockHeader : BlockHeader
        {
            public DigiByteBlockHeader(DigiByteConsensusFactory factory)
            {
                Factory = factory;
            }

            public DigiByteConsensusFactory Factory { get; }

            // The algorithm is encoded in bits 8-11 of the version (DigiByte Core CBlockHeader::GetAlgo)
            public DigiByteAlgo Algo => (Version & (15 << 8)) switch
            {
                0 << 8 => DigiByteAlgo.Scrypt,
                2 << 8 => DigiByteAlgo.SHA256D,
                4 << 8 => DigiByteAlgo.Groestl,
                6 << 8 => DigiByteAlgo.Skein,
                8 << 8 => DigiByteAlgo.Qubit,
                14 << 8 => DigiByteAlgo.Odo,
                _ => DigiByteAlgo.Unknown
            };

            public override uint256 GetPoWHash()
            {
                var headerBytes = this.ToBytes();
                switch (Algo)
                {
                    case DigiByteAlgo.SHA256D:
                        return GetHash();
                    case DigiByteAlgo.Scrypt:
                        return new uint256(SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32));
                    case DigiByteAlgo.Groestl:
                        return new uint256(Hashes.SHA256(HashFactory.Crypto.SHA3.CreateGroestl512().ComputeBytes(headerBytes).GetBytes()));
                    case DigiByteAlgo.Skein:
                        return new uint256(Hashes.SHA256(HashFactory.Crypto.SHA3.CreateSkein512_Custom().ComputeBytes(headerBytes).GetBytes()));
                    case DigiByteAlgo.Qubit:
                    {
                        var hash = HashFactory.Crypto.SHA3.CreateLuffa512().ComputeBytes(headerBytes).GetBytes();
                        hash = HashFactory.Crypto.SHA3.CreateCubeHash512().ComputeBytes(hash).GetBytes();
                        hash = HashFactory.Crypto.SHA3.CreateSHAvite3_512_Custom().ComputeBytes(hash).GetBytes();
                        hash = HashFactory.Crypto.SHA3.CreateSIMD512().ComputeBytes(hash).GetBytes();
                        hash = HashFactory.Crypto.SHA3.CreateEcho512().ComputeBytes(hash).GetBytes();
                        return new uint256(hash.Take(32).ToArray());
                    }
                    case DigiByteAlgo.Odo:
                        return new uint256(OdoCrypt.Hash(headerBytes, Factory.GetOdoCrypt(nTime)));
                    default:
                        // Same as DigiByte Core: an always-invalid PoW hash
                        return new uint256(Enumerable.Repeat((byte)0xff, 32).ToArray());
                }
            }
        }

        public class DigiByteBlock : Block
        {
            public DigiByteBlock(DigiByteBlockHeader header) : base(header)
            {
            }

            public override ConsensusFactory GetConsensusFactory()
            {
                return ((DigiByteBlockHeader)Header).Factory;
            }
        }
#pragma warning restore CS0618 // Type or member is obsolete

        protected override NetworkBuilder CreateMainnet()
        {
	        var builder = new NetworkBuilder();

	        builder.SetName("dgb-main")
		        .AddAlias("dgb-mainnet")
		        .AddAlias("digibyte-main")
		        .SetConsensus(new Consensus
		        {
			        SubsidyHalvingInterval = 210000,
			        MajorityEnforceBlockUpgrade = 750,
			        MajorityRejectBlockOutdated = 950,
			        MajorityWindow = 1000,
			        SupportSegwit = true,
			        SupportTaproot = true,
			        ConsensusFactory = DigiByteConsensusFactory.Mainnet
		        })
		        .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, [30])
		        .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, [63])
		        .SetBase58Bytes(Base58Type.SECRET_KEY, [128])
		        .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, [0x04, 0x88, 0xB2, 0x1E])
		        .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, [0x04, 0x88, 0xAD, 0xE4])
		        .SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("dgb"))
		        .SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("dgb"))
		        .SetBech32(Bech32Type.TAPROOT_ADDRESS, Encoders.Bech32("dgb"))
		        .SetMagic(0xDAB6C3FA)
		        .SetPort(12024)
		        .SetRPCPort(14022)
		        .SetMaxP2PVersion(70017) // DigiByte Core MIN_PEER_PROTO_VERSION
		        .SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000ad0f7d7518fc1e90ed28bd0e444ccd8e24d94688355705ed2142006b49d9dd726a62d052f0ff0f1e245925000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d01044555534120546f6461793a2031302f4a616e2f323031342c205461726765743a20446174612073746f6c656e2066726f6d20757020746f203131304d20637573746f6d657273ffffffff01401f0000000000000200ac00000000")
		        .AddDNSSeeds([
			        new DNSSeedData("seed.digibyte.io", "seed.digibyte.io"),
			        new DNSSeedData("seed.diginode.tools", "seed.diginode.tools"),
			        new DNSSeedData("seed.digibyte.link", "seed.digibyte.link"),
			        new DNSSeedData("seed.aroundtheblock.app", "seed.aroundtheblock.app"),
			        new DNSSeedData("seed.tuyul.cc", "seed.tuyul.cc")
		        ]);

	        return builder;
        }

        protected override NetworkBuilder CreateTestnet()
        {
	        var builder = new NetworkBuilder()
		        .SetName("dgb-test")
		        .AddAlias("digibyte-testnet")
		        .AddAlias("digibyte-test")
		        .SetConsensus(new Consensus
		        {
			        SubsidyHalvingInterval = 210000,
			        MajorityEnforceBlockUpgrade = 750,
			        MajorityRejectBlockOutdated = 950,
			        MajorityWindow = 1000,
			        SupportSegwit = true,
			        SupportTaproot = true,
			        ConsensusFactory = DigiByteConsensusFactory.Testnet
		        })
		        .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, [0x7E])  // tD
		        .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, [0x8C]) // tS
		        .SetBase58Bytes(Base58Type.SECRET_KEY, [0xFE])      // tWIF
		        .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, [0x04, 0x35, 0x87, 0xCF])
		        .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, [0x04, 0x35, 0x83, 0x94])
		        .SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("dgbt"))
		        .SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("dgbt"))
		        .SetBech32(Bech32Type.TAPROOT_ADDRESS, Encoders.Bech32("dgbt"))
		        .SetMagic(0xE7B9C6FE)
		        .SetPort(12033)
		        .SetRPCPort(14026)
		        .SetMaxP2PVersion(70017) // DigiByte Core MIN_PEER_PROTO_VERSION
		        .SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000097c108c537584d093dec35631a8dc487fe01a98226b702c60672476a9fa5ec7680091b6af0ff0f1e899613000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4304ffff001d01043b44696769446f6c6c617220546573746e657432363a205243343420372d6f662d3335204f7261636c65205265736574206f6e204469676942797465ffffffff010040b743ba0000000200ac00000000")
		        .AddDNSSeeds([
			        new DNSSeedData("testnetseed.digibyte.io", "testnetseed.digibyte.io"),
			        new DNSSeedData("testnetseed.digibyte.link", "testnetseed.digibyte.link"),
			        new DNSSeedData("testnetseed.digibyte.services", "testnetseed.digibyte.services")
		        ]);

	        return builder;
        }

        protected override NetworkBuilder CreateRegtest()
        {
            var builder = new NetworkBuilder()
	            .SetName("dgb-regtest")
	            .AddAlias("digibyte-regtest")
	            .AddAlias("digibyte-reg")
	            .SetConsensus(new Consensus
	            {
		            SubsidyHalvingInterval = 150,
		            MajorityEnforceBlockUpgrade = 750,
		            MajorityRejectBlockOutdated = 950,
		            MajorityWindow = 1000,
		            SupportSegwit = true,
		            SupportTaproot = true,
		            ConsensusFactory = DigiByteConsensusFactory.Regtest
	            })
	            .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, [126])
	            .SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, [140])
	            .SetBase58Bytes(Base58Type.SECRET_KEY, [254])
	            .SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, [0x04, 0x35, 0x87, 0xCF])
	            .SetBase58Bytes(Base58Type.EXT_SECRET_KEY, [0x04, 0x35, 0x83, 0x94])
	            .SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("dgbrt"))
	            .SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("dgbrt"))
	            .SetBech32(Bech32Type.TAPROOT_ADDRESS, Encoders.Bech32("dgbrt"))
	            .SetMagic(0xDAB5BFFA)
	            .SetPort(18444)
	            .SetRPCPort(18443)
	            .SetMaxP2PVersion(70017) // DigiByte Core MIN_PEER_PROTO_VERSION
	            .SetGenesis(
		            "010000000000000000000000000000000000000000000000000000000000000000000000ad0f7d7518fc1e90ed28bd0e444ccd8e24d94688355705ed2142006b49d9dd723a22915affff7f20040000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d01044555534120546f6461793a2031302f4a616e2f323031342c205461726765743a20446174612073746f6c656e2066726f6d20757020746f203131304d20637573746f6d657273ffffffff01401f0000000000000200ac00000000");

            return builder;
        }
    }
}
