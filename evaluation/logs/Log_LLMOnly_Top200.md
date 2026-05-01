PS E:\DarkHotel-CapstoneProject\DarkHotel-CapstoneProject\Capstone_FPT\DarkHotel-Capstone\evaluation> python run_llm_only_zeroshot.py --dataset top200
======================================================================
DarkHotel — TRUE ZERO-SHOT LLM-ONLY BASELINE
Model: gemini-2.5-pro
Prompt: Raw Solidity code only. NO SWC hints, NO checklist,
        NO expert rules, NO Slither, NO RAG.
======================================================================

======================================================================
ZERO-SHOT LLM-ONLY — GPTScan Top200 (Safe Production Contracts)
Prompt: Raw code only. Any detection = False Positive.
======================================================================
Top200: 225 valid contracts, 78 skipped
  arbi: 5
  avax: 18
  bsc: 61
  eth: 78
  fantom: 19
  poly: 44
----------------------------------------------------------------------

[1/225] MRC20.sol (poly, 531 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.4s
    - Reentrancy (SWC-107)

[2/225] OwnedUpgradeabilityProxy.sol (eth, 208 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 23.0s

[3/225] FetchToken.sol (bsc, 1263 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 37.0s

[4/225] Usdc.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 40.2s
    - Unchecked Return Value (SWC-104)

[5/225] AnyswapV3ERC20.sol (fantom, 500 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.2s
    - Unchecked Return Value (SWC-104)

[6/225] ERC20Proxy.sol (eth, 1028 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 64.8s
    - Integer Overflow/Underflow (SWC-101)
    - Integer Overflow (SWC-101)
    - Integer Overflow (SWC-101)

[7/225] TomoE.sol (eth, 755 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 105.3s
    - Integer Overflow/Underflow (SWC-101)

[8/225] AnyswapV5ERC20.sol (fantom, 602 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 63.6s
    - Unchecked Return Value (SWC-104)
    - Integer Overflow/Underflow (SWC-101)

[9/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 55.5s
    - Integer Overflow/Underflow (SWC-101)

[10/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 52.9s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[11/225] YFI.sol (eth, 225 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 25.3s

[12/225] IbcToken.sol (eth, 1051 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 29.3s

[13/225] BAToken.sol (eth, 175 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 27.4s
    - Integer Overflow/Underflow (SWC-101)
    - Integer Overflow/Underflow (SWC-101)
    - Integer Overflow/Underflow (SWC-101)

[14/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 43.5s

[15/225] CakeToken.sol (bsc, 1092 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 35.7s
    - Integer Overflow/Underflow (SWC-101)

[16/225] BEP20Cosmos.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 15.8s

[17/225] Bora20v2.sol (poly, 3019 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 51.5s
    - Unchecked Return Value (SWC-104)
    - Integer Overflow/Underflow (SWC-101)

[18/225] MANAToken.sol (eth, 278 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 30.3s

[19/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 55.4s
    - Integer Overflow/Underflow (SWC-101)

[20/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 42.6s

[21/225] OneInch.sol (bsc, 1388 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 28.0s

[22/225] OneInch.sol (eth, 1118 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 30.1s

[23/225] MXToken.sol (eth, 147 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 83.8s
    - Reentrancy (SWC-107)
    - Unchecked Return Value (SWC-104)

[24/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 31.8s

[25/225] BridgeToken.sol (bsc, 688 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 46.0s

[26/225] BEP20Tezos.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 19.8s

[27/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 52.8s
    - Integer Overflow/Underflow (SWC-101)

[28/225] CrossChainCanonicalFRAX.sol (arbi, 1782 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 67.9s

[29/225] AudiusAdminUpgradeabilityProxy.sol (eth, 268 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 32.1s

[30/225] BitgetToken.sol (eth, 147 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 33.4s

[31/225] CrossChainCanonicalFXS.sol (poly, 1779 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 51.4s
    - Reentrancy (SWC-107)

[32/225] BitDAO.sol (eth, 1068 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 42.6s

[33/225] BEP20DAI.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 23.5s

[34/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 53.4s
    - Integer Overflow/Underflow (SWC-101)

[35/225] BEP20Zcash.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 22.3s

[36/225] UChildERC20Proxy.sol (poly, 172 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 25.2s

[37/225] OwnedUpgradeabilityProxy.sol (avax, 204 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 21.1s

[38/225] WAVES.sol (eth, 308 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 48.6s
    - Integer Overflow/Underflow (SWC-101)
    - Integer Overflow/Underflow (SWC-101)
    - Integer Overflow/Underflow (SWC-101)

[39/225] CurveDAO.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 74.1s
    - Unchecked Return Value (SWC-104)

[40/225] Uni.sol (eth, 582 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 37.3s
    - Integer Overflow/Underflow (SWC-101)
    - Integer Overflow/Underflow (SWC-101)

[41/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 40.0s

[42/225] AnyswapV5ERC20.sol (avax, 598 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 35.7s
    - Unchecked Return Value (SWC-104)

[43/225] CrossChainCanonicalFXS.sol (avax, 1779 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 40.6s
    - Integer Overflow/Underflow (SWC-101)

[44/225] BEP20Ethereum.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 21.3s

[45/225] WBTC.sol (eth, 659 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 43.6s

[46/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 53.7s
    - Integer Overflow/Underflow (SWC-101)

[47/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 51.3s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[48/225] BoraToken.sol (eth, 263 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 36.2s
    - Unchecked Return Value (SWC-104)
    - Unchecked Return Value (SWC-104)
    - Unchecked Return Value (SWC-104)

[49/225] UChildERC20Proxy.sol (poly, 182 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 32.0s

[50/225] YFI.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 69.3s
    - Unchecked Return Value (SWC-104)

[51/225] LEO.sol (eth, 730 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 52.7s
    - Reentrancy (SWC-107)
    - Unchecked Return Value (SWC-104)
    - Unchecked Return Value (SWC-104)

[52/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.8s
    - Integer Overflow/Underflow (SWC-101)

[53/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.4s
    - Integer Overflow/Underflow (SWC-101)

[54/225] BEP20UpgradeableProxy.sol (bsc, 503 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 28.0s

[55/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 27.1s

[56/225] BTC.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 56.1s
    - Unchecked Return Value (SWC-104)

[57/225] chiliZ.sol (eth, 645 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 54.0s

[58/225] BTT.sol (bsc, 1649 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 34.9s

[59/225] TransparentUpgradeableProxy.sol (bsc, 722 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 32.4s

[60/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.0s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[61/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 37.9s

[62/225] BEP20Cardano.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 18.8s

[63/225] ERC20Custom.sol (avax, 1292 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 38.3s

[64/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 50.0s
    - Integer Overflow/Underflow (SWC-101)

[65/225] BEP20BitcoinCash.sol (bsc, 604 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 20.5s

[66/225] BridgeToken.sol (avax, 674 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 40.2s

[67/225] AdminUpgradeabilityProxy.sol (eth, 304 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 125.9s
    - Reentrancy (SWC-107)

[68/225] CrossChainCanonicalFRAX.sol (poly, 1779 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 55.1s

[69/225] BscToken.sol (bsc, 174 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 15.9s

[70/225] WootradeNetwork.sol (eth, 111 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 30.4s
    - Integer Overflow/Underflow (SWC-101)
    - Integer Overflow/Underflow (SWC-101)

[71/225] Band.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 76.5s
    - Unchecked Return Value (SWC-104)
    - Unchecked Return Value (SWC-104)

[72/225] SXP.sol (bsc, 805 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 35.0s
    - Integer Overflow (SWC-101)
    - Integer Overflow (SWC-101)

[73/225] StandardToken.sol (eth, 235 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 18.8s

[74/225] TrustWalletToken.sol (bsc, 897 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 30.5s

[75/225] FantomToken.sol (eth, 620 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 50.0s
    - Unchecked Return Value (SWC-104)

[76/225] AdminUpgradeabilityProxy.sol (eth, 304 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 120.8s
    - Reentrancy (SWC-107)

[77/225] TRX.sol (eth, 1648 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 54.6s

[78/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 49.2s
    - Integer Overflow/Underflow (SWC-101)

[79/225] LinkToken.sol (eth, 295 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 30.4s
    - Unchecked Return Value (SWC-104)

[80/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 38.0s

[81/225] ChildERC20.sol (poly, 1521 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 49.4s

[82/225] BEP20USDT.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 19.3s

[83/225] BEP20EOS.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 22.9s

[84/225] SNX.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 40.5s
    - Unchecked Return Value (SWC-104)
    - Unchecked Return Value (SWC-104)

[85/225] BridgeToken.sol (avax, 803 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.9s
    - Reentrancy (SWC-107)
    - Unchecked Return Value (SWC-104)

[86/225] MiniMeToken.sol (eth, 600 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 58.9s
    - Integer Overflow/Underflow (SWC-101)
    - Reentrancy (SWC-107)
    - Unchecked Return Value (SWC-104)

[87/225] SingularityNetToken.sol (eth, 1441 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 33.8s

[88/225] Proxy.sol (eth, 36 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 15.5s

[89/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 35.6s

[90/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 45.8s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[91/225] AdminUpgradeabilityProxy.sol (poly, 343 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 21.7s

[92/225] BridgeToken.sol (avax, 740 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 63.8s
    - Unchecked Return Value (SWC-104)

[93/225] AnyswapV5ERC20.sol (fantom, 598 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 31.5s
    - Unchecked Return Value (SWC-104)

[94/225] GnosisToken.sol (eth, 151 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 27.5s
    - Integer Overflow (SWC-101)
    - Integer Overflow (SWC-101)

[95/225] PepeToken.sol (eth, 632 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 43.4s

[96/225] MaskToken.sol (eth, 646 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 30.1s

[97/225] Aave.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 57.7s

[98/225] SushiToken.sol (eth, 1037 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.2s
    - Integer Overflow/Underflow (SWC-101)

[99/225] HoloToken.sol (eth, 275 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 27.3s

[100/225] AdminUpgradeabilityProxy.sol (eth, 307 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 66.7s

[101/225] HBToken.sol (eth, 123 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 58.7s

[102/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.6s
    - Integer Overflow/Underflow (SWC-101)

[103/225] IoTeXNetwork.sol (eth, 496 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 21.7s

[104/225] BEP20Polkadot.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 20.0s

[105/225] BridgeToken.sol (avax, 674 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 37.2s

[106/225] BEP20Token.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 24.8s

[107/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 28.7s

[108/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 49.5s
    - Integer Overflow/Underflow (SWC-101)

[109/225] JasmyCoin.sol (eth, 547 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 23.1s

[110/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 35.9s

[111/225] AnyswapV4ERC20.sol (fantom, 586 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 54.7s
    - Unchecked Return Value (SWC-104)
    - Integer Overflow/Underflow (SWC-101)

[112/225] CrossChainCanonicalFXS.sol (fantom, 1779 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 38.3s
    - Integer Overflow/Underflow (SWC-101)

[113/225] MaticToken.sol (eth, 494 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 23.5s

[114/225] NewGolemNetworkToken.sol (eth, 650 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 28.0s
    - Integer Overflow (SWC-101)

[115/225] ANKRToken.sol (eth, 259 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 18.8s

[116/225] AnyswapV3ERC20.sol (fantom, 500 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 39.6s
    - Unchecked Return Value (SWC-104)

[117/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.7s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[118/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 49.7s
    - Integer Overflow/Underflow (SWC-101)

[119/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 37.4s

[120/225] BridgeToken.sol (avax, 740 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 68.6s
    - Reentrancy (SWC-107)
    - Unchecked Return Value (SWC-104)

[121/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 34.2s

[122/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 49.2s
    - Integer Overflow/Underflow (SWC-101)

[123/225] SwipeToken.sol (eth, 493 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 40.2s
    - Unchecked Return Value (SWC-104)

[124/225] Dai.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 48.3s
    - Unchecked Return Value (SWC-104)

[125/225] IbcToken.sol (eth, 1051 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 31.7s

[126/225] AdminUpgradeabilityProxy.sol (eth, 294 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 55.9s
    - Reentrancy (SWC-107)

[127/225] BridgeToken.sol (avax, 740 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 44.1s
    - Reentrancy (SWC-107)
    - Unchecked Return Value (SWC-104)

[128/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.8s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[129/225] DFI.sol (eth, 1351 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 32.2s

[130/225] BEP20BitcoinCash.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 19.2s

[131/225] wBeldex.sol (bsc, 666 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 32.6s

[132/225] CrossChainCanonicalFRAX.sol (bsc, 1779 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 56.1s

[133/225] IbcToken.sol (eth, 1051 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 31.6s

[134/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 41.6s

[135/225] TokenMintERC20Token.sol (eth, 493 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 48.0s

[136/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 26.8s

[137/225] OceanToken.sol (eth, 803 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 51.8s

[138/225] TransparentUpgradeableProxy.sol (avax, 703 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 28.1s

[139/225] BridgeToken.sol (avax, 740 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 50.2s
    - Unchecked Return Value (SWC-104)

[140/225] BridgeToken.sol (bsc, 688 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 39.6s

[141/225] AnyswapV5ERC20.sol (fantom, 598 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 32.1s
    - Unchecked Return Value (SWC-104)

[142/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.5s
    - Integer Overflow/Underflow (SWC-101)

[143/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 35.0s

[144/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.8s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[145/225] BridgeToken.sol (poly, 690 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 39.7s

[146/225] CrossChainCanonicalFXS.sol (arbi, 1782 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 72.5s

[147/225] DSToken.sol (eth, 474 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 76.5s

[148/225] CroToken.sol (eth, 637 lines)
  Expected: SAFE
  Predicted: UNKNOWN | TN | 35.1s

[149/225] FiatTokenProxy.sol (eth, 329 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 32.9s

[150/225] ANTv2.sol (eth, 216 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 19.5s
    - Integer Overflow/Underflow (SWC-101)

[151/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 45.3s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[152/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 38.9s

[153/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 33.6s

[154/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.8s
    - Integer Overflow/Underflow (SWC-101)

[155/225] CoinToken.sol (eth, 914 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 49.6s
    - Integer Overflow/Underflow (SWC-101)
    - Unchecked Return Value (SWC-104)

[156/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 28.0s

[157/225] BEP20BandProtocol.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 18.4s

[158/225] Sushi.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 51.3s

[159/225] AppProxyUpgradeable.sol (eth, 392 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 54.0s
    - Integer Overflow/Underflow (SWC-101)

[160/225] FetchToken.sol (eth, 1259 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 33.4s

[161/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 47.8s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[162/225] ChainLink.sol (fantom, 493 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 44.4s
    - Unchecked Return Value (SWC-104)
    - Unchecked Return Value (SWC-104)

[163/225] NexoToken.sol (eth, 475 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 65.5s

[164/225] CrowdsaleToken.sol (eth, 599 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 57.0s
    - Integer Overflow/Underflow (SWC-101)
    - Unchecked Return Value (SWC-104)

[165/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 48.0s
    - Integer Overflow/Underflow (SWC-101)

[166/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 37.4s

[167/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 27.4s

[168/225] BNB.sol (eth, 146 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 78.4s
    - Reentrancy (SWC-107)

[169/225] FiatTokenProxy.sol (avax, 386 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 63.5s

[170/225] BalancerGovernanceToken.sol (eth, 1494 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 32.1s
    - Integer Overflow/Underflow (SWC-101)

[171/225] BandToken.sol (eth, 514 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 33.6s

[172/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 28.0s

[173/225] AXSToken.sol (eth, 213 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 20.8s

[174/225] WBNB.sol (bsc, 744 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 33.4s
    - Integer Overflow (SWC-101)
    - Integer Overflow (SWC-101)

[175/225] LRC_v2.sol (eth, 275 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 35.1s

[176/225] AnyswapV5ERC20.sol (bsc, 602 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 32.4s
    - Unchecked Return Value (SWC-104)

[177/225] BridgeToken.sol (avax, 740 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 59.0s
    - Reentrancy (SWC-107)

[178/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 36.5s

[179/225] Comp.sol (eth, 301 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 25.2s
    - Integer Overflow/Underflow (SWC-101)
    - Integer Overflow/Underflow (SWC-101)

[180/225] ProxyERC20.sol (eth, 505 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 28.2s
    - Unchecked Return Value (SWC-104)
    - Unchecked Return Value (SWC-104)
    - Unchecked Return Value (SWC-104)

[181/225] ONUSToken.sol (poly, 651 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 24.1s

[182/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 47.4s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[183/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 47.9s
    - Integer Overflow/Underflow (SWC-101)

[184/225] BTT.sol (eth, 1649 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 36.7s

[185/225] Tribe.sol (eth, 386 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 26.3s
    - Integer Overflow/Underflow (SWC-101)

[186/225] CoinToken.sol (bsc, 1157 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 52.7s
    - Integer Overflow/Underflow (SWC-101)
    - Unchecked Return Value (SWC-104)

[187/225] GraphToken.sol (eth, 962 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 23.6s

[188/225] pONT.sol (eth, 576 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 25.0s

[189/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 30.8s

[190/225] TRX.sol (bsc, 1648 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 54.7s

[191/225] CrossChainCanonicalFRAX.sol (avax, 1779 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 35.1s
    - Integer Overflow/Underflow (SWC-101)

[192/225] SafePalToken.sol (bsc, 559 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 22.9s

[193/225] BridgeToken.sol (avax, 740 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 64.2s
    - Reentrancy (SWC-107)
    - Unchecked Return Value (SWC-104)

[194/225] Vyper_contract.sol (eth, 374 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 22.1s

[195/225] AnyswapV4ERC20.sol (avax, 606 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 44.2s
    - Unchecked Return Value (SWC-104)

[196/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 48.0s
    - Integer Overflow/Underflow (SWC-101)

[197/225] NXMToken.sol (eth, 444 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 18.7s

[198/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 50.1s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[199/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 47.0s
    - Reentrancy (SWC-107)
    - Integer Overflow/Underflow (SWC-101)

[200/225] TetherToken.sol (eth, 447 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 55.5s
    - Integer Overflow/Underflow (SWC-101)
    - Integer Overflow/Underflow (SWC-101)

[201/225] EURSToken.sol (eth, 887 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.1s
    - Integer Overflow/Underflow (SWC-101)

[202/225] CrossChainCanonicalFRAX.sol (fantom, 1779 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 35.6s
    - Integer Overflow (SWC-101)

[203/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 48.0s
    - Integer Overflow/Underflow (SWC-101)

[204/225] InjectiveToken.sol (eth, 704 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 29.4s

[205/225] ZRXToken.sol (eth, 140 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 31.3s

[206/225] CrossChainCanonicalFXS.sol (bsc, 1779 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 46.2s
    - Reentrancy (SWC-107)

[207/225] GateChainToken.sol (eth, 192 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 19.0s

[208/225] AVABBC.sol (avax, 628 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 43.9s

[209/225] BABBC.sol (bsc, 628 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 48.7s

[210/225] WABBC.sol (eth, 628 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 72.9s

[211/225] FABBC.sol (fantom, 628 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 59.3s

[212/225] MABBC.sol (poly, 628 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 33.7s

[213/225] BEP20Token.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 23.3s

[214/225] BridgeToken.sol (poly, 690 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 39.5s

[215/225] ACH.sol (eth, 652 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 33.0s

[216/225] AnkrBEP20Token.sol (bsc, 592 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 18.4s

[217/225] IMXToken.sol (eth, 750 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 29.2s

[218/225] ENJToken.sol (eth, 488 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 109.0s
    - Integer Overflow/Underflow (SWC-101)

[219/225] UChildERC20Proxy.sol (poly, 168 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 48.6s
    - Integer Overflow/Underflow (SWC-101)

[220/225] BEP20LINK.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 25.0s

[221/225] BEP20UpgradeableProxy.sol (bsc, 479 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 32.2s

[222/225] GMX.sol (arbi, 817 lines)
  Expected: SAFE
  Predicted: VULNERABLE | FP | 52.2s
    - Reentrancy (SWC-107)
    - Unchecked Return Value (SWC-104)

[223/225] TransparentUpgradeableProxy.sol (arbi, 684 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 36.0s

[224/225] BEP20Ontology.sol (bsc, 600 lines)
  Expected: SAFE
  Predicted: SAFE | TN | 22.9s

[225/225] TransparentUpgradeableProxy.sol (arbi, 490 lines)
  Expected: SAFE
    Error attempt 1: 429 RESOURCE_EXHAUSTED. {'error': {'code': 429, 'message': 'Resource exhausted. Please try again later. Please refer to
    Waiting 60s...
  Predicted: SAFE | TN | 116.1s

======================================================================
RESULTS — ZERO-SHOT LLM-ONLY on Top200
======================================================================

  TN: 125/225  |  FP: 100/225
  False Positive Rate: 44.44%
  Specificity: 55.56%

Per-Chain FPR:
  arbi        : 1/5 FP (20%)
  avax        : 11/18 FP (61%)
  bsc         : 6/61 FP (10%)
  eth         : 31/78 FP (40%)
  fantom      : 16/19 FP (84%)
  poly        : 35/44 FP (80%)

False Positive Type Distribution:
  Integer Overflow/Underflow: 66
  Unchecked Return Value: 45
  Reentrancy: 29
  Integer Overflow: 11

Avg time: 41.7s | Total: 167.8 min

Saved: E:\DarkHotel-CapstoneProject\DarkHotel-CapstoneProject\Capstone_FPT\DarkHotel-Capstone\evaluation\llm_zeroshot_results\zeroshot_top200_results.json

Done!