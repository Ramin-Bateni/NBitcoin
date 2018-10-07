using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.RPC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace NBitcoin.Acchoins
{
	public class CounosCash : NetworkSetBase
	{
		public static CounosCash Instance { get; } = new CounosCash();

		public override string CryptoCode => "CCH";

		private CounosCash()
		{

		}
		//Format visual studio
		//{({.*?}), (.*?)}
		//Tuple.Create(new byte[]$1, $2)
		static Tuple<byte[], int>[] pnSeed6_main = {};
		static Tuple<byte[], int>[] pnSeed6_test = {};

#pragma warning disable CS0618 // Type or member is obsolete
		public class CounosCashConsensusFactory : ConsensusFactory
		{
			private CounosCashConsensusFactory()
			{
			}

			public static CounosCashConsensusFactory Instance { get; } = new CounosCashConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new CounosCashBlockHeader();
			}
			public override Block CreateBlock()
			{
				return new CounosCashBlock(new CounosCashBlockHeader());
			}
		}

		public class CounosCashBlockHeader : BlockHeader
		{
			public override uint256 GetPoWHash()
			{
				var headerBytes = this.ToBytes();
				var h = NBitcoin.Crypto.SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
				return new uint256(h);
			}
		}

		public class CounosCashBlock : Block
		{
			public CounosCashBlock(CounosCashBlockHeader header) : base(header)
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return CounosCashConsensusFactory.Instance;
			}
		}

		public class CounosCashMainnetAddressStringParser : NetworkStringParser
		{
			public override bool TryParse<T>(string str, Network network, out T result)
			{
				if(str.StartsWith("Ltpv", StringComparison.OrdinalIgnoreCase) && typeof(T) == typeof(BitcoinExtKey))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x88;
						decoded[2] = 0xAD;
						decoded[3] = 0xE4;
						result = (T)(object)new BitcoinExtKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				if(str.StartsWith("Ltub", StringComparison.OrdinalIgnoreCase) && typeof(T) == typeof(BitcoinExtPubKey))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x88;
						decoded[2] = 0xB2;
						decoded[3] = 0x1E;
						result = (T)(object)new BitcoinExtPubKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				return base.TryParse(str, network, out result);
			}
		}

#pragma warning restore CS0618 // Type or member is obsolete

		protected override void PostInit()
		{
			RegisterDefaultCookiePath("CounosCash", new FolderName() { TestnetFolder = "testnet4" });
		}

		// ساخت شبکه میننت
		protected override NetworkBuilder CreateMainnet()
		{
			NetworkBuilder builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 840000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf"),
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(3.5 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = false,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 6048,
				MinerConfirmationWindow = 8064,
				CoinbaseMaturity = 100,
				LitecoinWorkCalculation = true,
				ConsensusFactory = CounosCashConsensusFactory.Instance
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 48 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 50 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 176 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetNetworkStringParser(new CounosCashMainnetAddressStringParser())
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("cch"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("cch"))
			.SetMagic(0xdbb6c0fb)
			.SetPort(9333)
			.SetRPCPort(9332)
			.SetName("cch-main")
			.AddAlias("cch-mainnet")
			.AddAlias("counoscash-mainnet")
			.AddAlias("counoscash-main")
			.AddDNSSeeds(new[]
			{
				//TODO باید بعدا بررسی شود و اضافه شود به اینجا
			})
			.AddSeeds(ToSeed(pnSeed6_main))
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97b9aa8e4ef0ff0f1ecd513f7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000");
			return builder;
		}

		// ساخت شبکه تستنت
		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 840000,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 1000,
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(3.5 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = true,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1512,
				MinerConfirmationWindow = 2016,
				CoinbaseMaturity = 100,
				LitecoinWorkCalculation = true,
				ConsensusFactory = CounosCashConsensusFactory.Instance
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 58 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tcch"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tcch"))
			.SetMagic(0xf1c8d2fd)
			.SetPort(19335)
			.SetRPCPort(19332)
			.SetName("cch-test")
			.AddAlias("cch-testnet")
			.AddAlias("counoscash-test")
			.AddAlias("counoscash-testnet")
			.AddDNSSeeds(new[]
			{
				//TODO باید بعدا بررسی شود و اضافه شود به اینجا
			})
			.AddSeeds(ToSeed(pnSeed6_test))
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97f60ba158f0ff0f1ee17904000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000");
			return builder;
		}

		// ساخت شبکه رجتست
		protected override NetworkBuilder CreateRegtest()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 150,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 144,
				PowLimit = new Target(new uint256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(3.5 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = true,
				MinimumChainWork = uint256.Zero,
				PowNoRetargeting = true,
				RuleChangeActivationThreshold = 108,
				MinerConfirmationWindow = 2016,
				CoinbaseMaturity = 100,
				LitecoinWorkCalculation = true,
				ConsensusFactory = CounosCashConsensusFactory.Instance
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 58 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tcch"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tcch"))
			.SetMagic(0xdab5bffa)
			.SetPort(19444)
			.SetRPCPort(19332)
			.SetName("cch-reg")
			.AddAlias("cch-regtest")
			.AddAlias("counoscash-reg")
			.AddAlias("counoscash-regtest")
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97dae5494dffff7f20000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000");
			return builder;
		}
	}
}
