PS E:\DarkHotel-CapstoneProject\DarkHotel-CapstoneProject\Capstone_FPT\DarkHotel-Capstone\evaluation> python run_smartbugs_eval.py
======================================================================
DarkHotel Evaluation - SmartBugs-Curated Dataset (CRAG 0.65)
======================================================================
API Status: online
Model: gemini-2.5-pro

Contracts to evaluate: 98
  Integer Overflow/Underflow: 15
  Reentrancy: 31
  Unchecked Return Value: 52
----------------------------------------------------------------------

[1/98] 0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 58.2s
  Detected: Reentrancy (SWC-107)

[2/98] 0x23a91059fdc9579a9fbd0edc5f2ea0bfdb70deb4.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 66.1s
  Detected: Reentrancy (SWC-107)

[3/98] 0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 68.6s
  Detected: Reentrancy (SWC-107)

[4/98] 0x4e73b32ed6c35f570686b89848e5f39f20ecc106.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 64.0s
  Detected: Reentrancy (SWC-107), Integer Underflow (SWC-101)

[5/98] 0x561eac93c92360949ab1f1403323e6db345cbf31.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 56.4s
  Detected: Reentrancy (SWC-107), Integer Overflow (SWC-101)

[6/98] 0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 61.0s
  Detected: Reentrancy (SWC-107), Unchecked Return Value (SWC-104), Integer Underflow (SWC-101)

[7/98] 0x7541b76cb60f4c60af330c208b0623b7f54bf615.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 46.7s
  Detected: Reentrancy (SWC-107)

[8/98] 0x7a8721a9d64c74da899424c1b52acbf58ddc9782.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 55.5s
  Detected: Reentrancy (SWC-107)

[9/98] 0x7b368c4e805c3870b6c49a3f1f49f69af8662cf3.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 64.7s
  Detected: Reentrancy (SWC-107), Integer Underflow (SWC-101)

[10/98] 0x8c7777c45481dba411450c228cb692ac3d550344.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 61.7s
  Detected: Reentrancy (SWC-107), Integer Underflow (SWC-101)

[11/98] 0x93c32845fae42c83a70e5f06214c8433665c2ab5.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 54.0s
  Detected: Reentrancy (SWC-107)

[12/98] 0x941d225236464a25eb18076df7da6a91d0f95e9e.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 57.5s
  Detected: Reentrancy (SWC-107), Reentrancy (SWC-107)

[13/98] 0x96edbe868531bd23a6c05e9d0c424ea64fb1b78b.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 60.0s
  Detected: Reentrancy (SWC-107), Integer Overflow (SWC-101)

[14/98] 0xaae1f51cf3339f18b6d3f3bdc75a5facd744b0b8.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 39.9s
  Detected: Reentrancy (SWC-107)

[15/98] 0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 52.4s
  Detected: Reentrancy (SWC-107)

[16/98] 0xb93430ce38ac4a6bb47fb1fc085ea669353fd89e.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 65.4s
  Detected: Reentrancy (SWC-107)

[17/98] 0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 50.4s
  Detected: Reentrancy (SWC-107)

[18/98] 0xbe4041d55db380c5ae9d4a9b9703f1ed4e7e3888.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 56.3s
  Detected: Reentrancy (SWC-107)

[19/98] 0xcead721ef5b11f1a7b530171aab69b16c5e66b6e.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 39.1s
  Detected: Reentrancy (SWC-107)

[20/98] 0xf015c35649c82f5467c9c74b7f28ee67665aad68.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 55.5s
  Detected: Reentrancy (SWC-107)

[21/98] etherbank.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 49.5s
  Detected: Reentrancy (SWC-107), Integer Overflow (SWC-101)

[22/98] etherstore.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 46.9s
  Detected: Reentrancy (SWC-107)

[23/98] modifier_reentrancy.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 56.5s
  Detected: Reentrancy (SWC-107)

[24/98] reentrance.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 41.7s
  Detected: Reentrancy (SWC-107)

[25/98] reentrancy_bonus.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 47.8s
  Detected: Reentrancy (SWC-107)

[26/98] reentrancy_cross_function.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 49.3s
  Detected: Reentrancy (SWC-107)

[27/98] reentrancy_dao.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 46.4s
  Detected: Reentrancy (SWC-107), Integer Underflow (SWC-101)

[28/98] reentrancy_insecure.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 35.8s
  Detected: Reentrancy (SWC-107)

[29/98] reentrancy_simple.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 45.2s
  Detected: Reentrancy (SWC-107)

[30/98] simple_dao.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 56.6s
  Detected: Reentrancy (SWC-107), Unchecked Return Value (SWC-104)

[31/98] spank_chain_payment.sol
  Expected: VULNERABLE (Reentrancy)
  Predicted: VULNERABLE | OK | 111.4s
  Detected: Reentrancy (SWC-107), Integer Overflow/Underflow (SWC-101)

[32/98] BECToken.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 70.0s
  Detected: Integer Overflow (SWC-101)

[33/98] insecure_transfer.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 37.3s
  Detected: Integer Overflow (SWC-101)

[34/98] integer_overflow_1.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 28.9s
  Detected: Integer Overflow (SWC-101)

[35/98] integer_overflow_add.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 31.2s
  Detected: Integer Overflow (SWC-101)

[36/98] integer_overflow_benign_1.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: SAFE | MISSED | 31.1s

[37/98] integer_overflow_mapping_sym_1.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 36.1s
  Detected: Integer Underflow (SWC-101)

[38/98] integer_overflow_minimal.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 29.1s
  Detected: Integer Underflow (SWC-101)

[39/98] integer_overflow_mul.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 35.0s
  Detected: Integer Overflow (SWC-101)

[40/98] integer_overflow_multitx_multifunc_feasible.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 56.7s
  Detected: Integer Underflow (SWC-101)

[41/98] integer_overflow_multitx_onefunc_feasible.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 28.6s
  Detected: Integer Underflow (SWC-101)

[42/98] overflow_simple_add.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 28.8s
  Detected: Integer Overflow (SWC-101)

[43/98] overflow_single_tx.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 56.4s
  Detected: Integer Overflow/Underflow (SWC-101), Integer Overflow/Underflow (SWC-101), Integer Overflow/Underflow (SWC-101)

[44/98] timelock.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 39.7s
  Detected: Integer Overflow (SWC-101)

[45/98] token.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 49.5s
  Detected: Integer Underflow (SWC-101)

[46/98] tokensalechallenge.sol
  Expected: VULNERABLE (Integer Overflow/Underflow)
  Predicted: VULNERABLE | OK | 78.2s
  Detected: Integer Overflow (SWC-101), Integer Overflow (SWC-101), Integer Overflow (SWC-101)

[47/98] 0x07f7ecb66d788ab01dc93b9b71a88401de7d0f2e.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 83.7s
  Detected: Unchecked Low-Level Call (SWC-104), Reentrancy (SWC-107)

[48/98] 0x0cbe050f75bc8f8c2d6c0d249fea125fd6e1acc9.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 41.9s
  Detected: Unchecked Return Value (SWC-104)

[49/98] 0x19cf8481ea15427a98ba3cdd6d9e14690011ab10.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 155.5s
  Detected: Unchecked Return Value (SWC-104), Reentrancy (SWC-107), Integer Overflow/Underflow (SWC-101)

[50/98] 0x2972d548497286d18e92b5fa1f8f9139e5653fd2.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 43.8s
  Detected: Unchecked Return Value (SWC-104)

[51/98] 0x39cfd754c85023648bf003bea2dd498c5612abfa.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 69.0s
  Detected: Reentrancy (SWC-107), Unchecked Return Value (SWC-104)

[52/98] 0x3a0e9acd953ffc0dd18d63603488846a6b8b2b01.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 64.6s
  Detected: Reentrancy (SWC-107), Unchecked Return Value (SWC-104), Integer Overflow (SWC-101)

[53/98] 0x3e013fc32a54c4c5b6991ba539dcd0ec4355c859.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 66.0s
  Detected: Unchecked Low-Level Call (SWC-104), Integer Overflow (SWC-101)

[54/98] 0x3f2ef511aa6e75231e4deafc7a3d2ecab3741de2.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 48.0s
  Detected: Unchecked Return Value (SWC-104)

[55/98] 0x4051334adc52057aca763453820cb0e045076ef3.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 53.9s
  Detected: Unchecked Low-Level Call (SWC-104), Reentrancy (SWC-107)

[56/98] 0x4a66ad0bca2d700f11e1f2fc2c106f7d3264504c.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 55.8s
  Detected: Unchecked Return Value (SWC-104), Integer Overflow (SWC-101)

[57/98] 0x4b71ad9c1a84b9b643aa54fdd66e2dec96e8b152.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 41.0s
  Detected: Unchecked Low-Level Call (SWC-104)

[58/98] 0x524960d55174d912768678d8c606b4d50b79d7b1.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 42.2s
  Detected: Unchecked Return Value (SWC-104)

[59/98] 0x52d2e0f9b01101a59b38a3d05c80b7618aeed984.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 60.7s
  Detected: Unchecked Return Value (SWC-104), Unchecked Return Value (SWC-104)

[60/98] 0x5aa88d2901c68fda244f1d0584400368d2c8e739.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 80.8s
  Detected: Unchecked Low-Level Call (SWC-104), Integer Overflow (SWC-101)

[61/98] 0x610495793564aed0f9c7fc48dc4c7c9151d34fd6.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 43.5s
  Detected: Unchecked Return Value (SWC-104)

[62/98] 0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 57.3s
  Detected: Reentrancy (SWC-107), Unchecked Return Value (SWC-104)

[63/98] 0x663e4229142a27f00bafb5d087e1e730648314c3.sol
  Expected: VULNERABLE (Unchecked Return Value)
  ERROR: HTTP 500: {"detail":"Request to model 'rerank-2.5' failed. The max allowed tokens per submitted batch is 600000. Your batch has 707403 tokens after truncation. Please lower the number of tokens in the batch."}

[64/98] 0x70f9eddb3931491aab1aeafbc1e7f1ca2a012db4.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 52.7s
  Detected: Unchecked Return Value (SWC-104)

[65/98] 0x78c2a1e91b52bca4130b6ed9edd9fbcfd4671c37.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 57.9s
  Detected: Unchecked Return Value (SWC-104)

[66/98] 0x7a4349a749e59a5736efb7826ee3496a2dfd5489.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 47.4s
  Detected: Unchecked Return Value (SWC-104)

[67/98] 0x7d09edb07d23acb532a82be3da5c17d9d85806b4.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 70.0s
  Detected: Reentrancy (SWC-107), Unchecked Return Value (SWC-104)

[68/98] 0x806a6bd219f162442d992bdc4ee6eba1f2c5a707.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 46.1s
  Detected: Unchecked Return Value (SWC-104)

[69/98] 0x84d9ec85c9c568eb332b7226a8f826d897e0a4a8.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 46.6s
  Detected: Unchecked Return Value (SWC-104)

[70/98] 0x89c1b3807d4c67df034fffb62f3509561218d30b.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 91.4s
  Detected: Integer Underflow (SWC-101), Unchecked Return Value (SWC-104)

[71/98] 0x8fd1e427396ddb511533cf9abdbebd0a7e08da35.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 76.5s
  Detected: Reentrancy (SWC-107), Unchecked Return Value (SWC-104), Unchecked Return Value (SWC-104)

[72/98] 0x958a8f594101d2c0485a52319f29b2647f2ebc06.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 56.2s
  Detected: Unchecked Low-Level Call (SWC-104)

[73/98] 0x9d06cbafa865037a01d322d3f4222fa3e04e5488.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 56.6s
  Detected: Unchecked Return Value (SWC-104), Unchecked Return Value (SWC-104)

[74/98] 0xa1fceeff3acc57d257b917e30c4df661401d6431.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 48.5s
  Detected: Unchecked Return Value (SWC-104)

[75/98] 0xa46edd6a9a93feec36576ee5048146870ea2c3ae.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 43.3s
  Detected: Unchecked Return Value (SWC-104)

[76/98] 0xb0510d68f210b7db66e8c7c814f22680f2b8d1d6.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 67.3s
  Detected: Unchecked Return Value (SWC-104), Unchecked Return Value (SWC-104)

[77/98] 0xb11b2fed6c9354f7aa2f658d3b4d7b31d8a13b77.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 64.6s
  Detected: Unchecked Return Value (SWC-104), Integer Overflow (SWC-101)

[78/98] 0xb37f18af15bafb869a065b61fc83cfc44ed9cc27.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 41.6s
  Detected: Unchecked Low-Level Call (SWC-104)

[79/98] 0xb620cee6b52f96f3c6b253e6eea556aa2d214a99.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 92.3s
  Detected: Unchecked Return Value (SWC-104)

[80/98] 0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 46.8s
  Detected: Reentrancy (SWC-107), Unchecked Return Value (SWC-104)

[81/98] 0xbaa3de6504690efb064420d89e871c27065cdd52.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 75.9s
  Detected: Unchecked Low-Level Call (SWC-104), Integer Overflow (SWC-101)

[82/98] 0xbebbfe5b549f5db6e6c78ca97cac19d1fb03082c.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 53.3s
  Detected: Unchecked Low-Level Call (SWC-104)

[83/98] 0xd2018bfaa266a9ec0a1a84b061640faa009def76.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 42.7s
  Detected: Unchecked Low-Level Call (SWC-104)

[84/98] 0xd5967fed03e85d1cce44cab284695b41bc675b5c.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 42.6s
  Detected: Unchecked Return Value (SWC-104)

[85/98] 0xdb1c55f6926e7d847ddf8678905ad871a68199d2.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 63.3s
  Detected: Unchecked Return Value (SWC-104)

[86/98] 0xe09b1ab8111c2729a76f16de96bc86a7af837928.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 97.3s
  Detected: Reentrancy (SWC-107), Unchecked Return Value (SWC-104), Integer Overflow/Underflow (SWC-101)

[87/98] 0xe4eabdca81e31d9acbc4af76b30f532b6ed7f3bf.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 57.0s
  Detected: Unchecked Return Value (SWC-104)

[88/98] 0xe82f0742a71a02b9e9ffc142fdcb6eb1ed06fb87.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 55.8s
  Detected: Unchecked Low-Level Call (SWC-104)

[89/98] 0xe894d54dca59cb53fe9cbc5155093605c7068220.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 54.2s
  Detected: Unchecked Return Value (SWC-104), Integer Overflow (SWC-101)

[90/98] 0xec329ffc97d75fe03428ae155fc7793431487f63.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 83.6s
  Detected: Integer Overflow (SWC-101), Unchecked Return Value (SWC-104)

[91/98] 0xf2570186500a46986f3139f65afedc2afe4f445d.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 36.3s
  Detected: Unchecked Return Value (SWC-104)

[92/98] 0xf29ebe930a539a60279ace72c707cba851a57707.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 81.6s
  Detected: Reentrancy (SWC-107), Unchecked Low-Level Call (SWC-104)

[93/98] 0xf70d589d76eebdd7c12cc5eec99f8f6fa4233b9e.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 57.9s
  Detected: Unchecked Return Value (SWC-104)

[94/98] etherpot_lotto.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 76.6s
  Detected: Integer Overflow (SWC-101), Unchecked Return Value (SWC-104)

[95/98] king_of_the_ether_throne.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 81.2s
  Detected: Unchecked Return Value (SWC-104), Integer Overflow (SWC-101), Unchecked Return Value (SWC-104)

[96/98] lotto.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 47.3s
  Detected: Unchecked Return Value (SWC-104), Unchecked Return Value (SWC-104)

[97/98] mishandled.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 37.5s
  Detected: Unchecked Return Value (SWC-104)

[98/98] unchecked_return_value.sol
  Expected: VULNERABLE (Unchecked Return Value)
  Predicted: VULNERABLE | OK | 37.9s
  Detected: Unchecked Return Value (SWC-104)

======================================================================
PART 1 — DETECTION RESULTS
======================================================================

Detection (all contracts are vulnerable):
  Detected (TP):  96/97
  Missed (FN):    1/97

  Recall (Detection Rate): 98.97%
  Type Accuracy:           98.97%

Per-Category Breakdown:
  Integer Overflow/Underflow    : 14/15 detected (93%), type match: 14/15 (93%)
  Reentrancy                    : 31/31 detected (100%), type match: 31/31 (100%)
  Unchecked Return Value        : 51/51 detected (100%), type match: 51/51 (100%)

Avg Analysis Time: 56.2s
Total Time: 90.9 min

======================================================================
PART 2 — PER-TYPE RECALL
======================================================================
  Reentrancy                          (SWC-107): 31/31 = 100%
  Integer Overflow/Underflow          (SWC-101): 14/15 = 93%
  Unchecked Return Value              (SWC-104): 51/51 = 100%
  Overall                                   : 96/97 = 99%

  MISSED contracts:
    integer_overflow_benign_1.sol — expected SWC-101, got []

======================================================================
PART 3 — SECONDARY FINDINGS ANALYSIS
======================================================================
  Total secondary findings: 36
  Verified real:            33
  False alarms:             3

  Verified real rate:  91.7%
  False alarm rate:   8.3%

  False alarm details:

    Integer Overflow (SWC-101) — 1 false alarms:
      0x19cf8481ea15427a98ba3cdd6d9e14690011ab10.sol: SafeMath is used

    Reentrancy (SWC-107) — 2 false alarms:
      0x19cf8481ea15427a98ba3cdd6d9e14690011ab10.sol: No .call{value:}() — only .send()/.transfer() (2300 gas)
      0x4051334adc52057aca763453820cb0e045076ef3.sol: No .call{value:}() — only .send()/.transfer() (2300 gas)

======================================================================
SUMMARY
======================================================================
  Primary Recall:       96/97 = 99%
  Secondary Accuracy:   33/36 verified real (92%)
  False Alarm Rate:     3/36 (8%)
  Avg Analysis Time:    56.2s
======================================================================

Results saved to: E:\DarkHotel-CapstoneProject\DarkHotel-CapstoneProject\Capstone_FPT\DarkHotel-Capstone\evaluation\smartbugs_evaluation_results_crag065.json