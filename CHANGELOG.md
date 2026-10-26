# Changelog

## [0.9.0](https://github.com/syscoin/zksync-airbender-prover/compare/v0.8.2...v0.9.0) (2026-10-26)


### ⚠ BREAKING CHANGES

* V8 program binding, 100-bit proving, zksync-os v0.4.0 binary ([#153](https://github.com/syscoin/zksync-airbender-prover/issues/153))
* update prover stack for v8  ([#137](https://github.com/syscoin/zksync-airbender-prover/issues/137))
* update prover stack for v31 ([#131](https://github.com/syscoin/zksync-airbender-prover/issues/131))
* Update provers to v1.3.1 ([#115](https://github.com/syscoin/zksync-airbender-prover/issues/115))
* Update prover stack for protocol v1.3 ([#104](https://github.com/syscoin/zksync-airbender-prover/issues/104))
* Poll a list of sequencers in provers ([#97](https://github.com/syscoin/zksync-airbender-prover/issues/97))
* Update prover stack for protocol v1.2 ([#98](https://github.com/syscoin/zksync-airbender-prover/issues/98))
* Update prover stack for protocol v1.1 ([#80](https://github.com/syscoin/zksync-airbender-prover/issues/80))

### Features

* Adapt prover to use 0.4.x airbender/wrapper ([#44](https://github.com/syscoin/zksync-airbender-prover/issues/44)) ([f7e27d4](https://github.com/syscoin/zksync-airbender-prover/commit/f7e27d4feb9d3fa8aa638437123a3305ad54c560))
* Add `ulimit -s` command for prover-snark ([#53](https://github.com/syscoin/zksync-airbender-prover/issues/53)) ([2683d4d](https://github.com/syscoin/zksync-airbender-prover/commit/2683d4dcbbb8d7c6b386cb0eb582483ca3b5cf3a))
* Add disable_zk flag to CLI ([#95](https://github.com/syscoin/zksync-airbender-prover/issues/95)) ([4a74a09](https://github.com/syscoin/zksync-airbender-prover/commit/4a74a0957b59d20e49ab0acd933ac22b878e341a))
* add release-bins.yaml ([#118](https://github.com/syscoin/zksync-airbender-prover/issues/118)) ([f403358](https://github.com/syscoin/zksync-airbender-prover/commit/f4033580701eb7cfc11d527bc1b6368aa6e068b8))
* Add ZK to SNARK ([#92](https://github.com/syscoin/zksync-airbender-prover/issues/92)) ([5c66d6b](https://github.com/syscoin/zksync-airbender-prover/commit/5c66d6b088322e552da745e2a6925ee15c3fbafb))
* adjust fri prover buckets ([#81](https://github.com/syscoin/zksync-airbender-prover/issues/81)) ([356bd10](https://github.com/syscoin/zksync-airbender-prover/commit/356bd1060f0744a5774bb318f94109ac08787196))
* Adjust FRI prover time taken buckets ([#79](https://github.com/syscoin/zksync-airbender-prover/issues/79)) ([920044b](https://github.com/syscoin/zksync-airbender-prover/commit/920044bbd469d53b9b82597029767f49318652fe))
* allow passing prover_name in params ([#103](https://github.com/syscoin/zksync-airbender-prover/issues/103)) ([32f084b](https://github.com/syscoin/zksync-airbender-prover/commit/32f084bf8a140d14c02fe8e1a5fbcd5df69587be))
* bump zksync-os binary to 0.0.13 ([#38](https://github.com/syscoin/zksync-airbender-prover/issues/38)) ([ecc28c4](https://github.com/syscoin/zksync-airbender-prover/commit/ecc28c410968c143b60b35bddf054cdb9326d307))
* bump zksync-os binary to 0.0.21 ([#55](https://github.com/syscoin/zksync-airbender-prover/issues/55)) ([7abf9e7](https://github.com/syscoin/zksync-airbender-prover/commit/7abf9e79f1adfeac8b81f652f7231a32719c8adb))
* Centralize timing metrics and improve retry logs ([#107](https://github.com/syscoin/zksync-airbender-prover/issues/107)) ([ba7b320](https://github.com/syscoin/zksync-airbender-prover/commit/ba7b320ffa0a3bbc0db3e559f44a28d4d63bcd7f))
* Expose zksync-airbender-prover as image ([#127](https://github.com/syscoin/zksync-airbender-prover/issues/127)) ([78310c5](https://github.com/syscoin/zksync-airbender-prover/commit/78310c5434b8c65ac460d6d89ff851146a1eae1e))
* Generate SNARK precomputes on start-up ([#66](https://github.com/syscoin/zksync-airbender-prover/issues/66)) ([28d3a9e](https://github.com/syscoin/zksync-airbender-prover/commit/28d3a9ebb33e70573cd0cc1803616c786868a1a7))
* Improve pick SNARK UX ([#76](https://github.com/syscoin/zksync-airbender-prover/issues/76)) ([14f2bef](https://github.com/syscoin/zksync-airbender-prover/commit/14f2beff970c1b3654a97aa03fa28830ceeb5510))
* Log unsent SNARK blocks ([#84](https://github.com/syscoin/zksync-airbender-prover/issues/84)) ([ff3c6fa](https://github.com/syscoin/zksync-airbender-prover/commit/ff3c6fae52e42eee3c6d9e476b87e2291c29b98a))
* make Args::disable_zk public ([#99](https://github.com/syscoin/zksync-airbender-prover/issues/99)) ([299d950](https://github.com/syscoin/zksync-airbender-prover/commit/299d9504c25293250fc4ec5d14909ee1d9ee56b4))
* make the number of circuits configurable ([#40](https://github.com/syscoin/zksync-airbender-prover/issues/40)) ([ca10cff](https://github.com/syscoin/zksync-airbender-prover/commit/ca10cff1eef84f60d9c50cef4ef29e01d36f73cf))
* Metrics for prover ([#68](https://github.com/syscoin/zksync-airbender-prover/issues/68)) ([e0d13fa](https://github.com/syscoin/zksync-airbender-prover/commit/e0d13fa45b04d3fb8d5a31e5d7ba555c41d2842b))
* Poll a list of sequencers in provers ([#97](https://github.com/syscoin/zksync-airbender-prover/issues/97)) ([36b589f](https://github.com/syscoin/zksync-airbender-prover/commit/36b589f8b041bb82dd86719e626fedd3b9f8c912))
* Proof client peek functions ([#85](https://github.com/syscoin/zksync-airbender-prover/issues/85)) ([a9d8eb7](https://github.com/syscoin/zksync-airbender-prover/commit/a9d8eb71f74e1da422393d25051190a32147c852))
* Protocol Upgrade support ([#96](https://github.com/syscoin/zksync-airbender-prover/issues/96)) ([320a829](https://github.com/syscoin/zksync-airbender-prover/commit/320a8292adc86100b97db95be7c4cb5624e82d64))
* **prover:** add adaptive SNARK queue trigger ([4a992d3](https://github.com/syscoin/zksync-airbender-prover/commit/4a992d358b67342891b34779cf096df5c2cce0ee))
* **prover:** add adaptive SNARK queue trigger ([d924aac](https://github.com/syscoin/zksync-airbender-prover/commit/d924aacd12a87f8b84f049afdc7bb617da35f741))
* **prover:** add FlashBoot Serverless FRI workers ([1e1214f](https://github.com/syscoin/zksync-airbender-prover/commit/1e1214f66c8dc7b02052e01b0a3b977c64c894e2))
* **prover:** add FlashBoot Serverless FRI workers ([4a6d929](https://github.com/syscoin/zksync-airbender-prover/commit/4a6d92977268f278b4cc72a82a9a64a1e0843ee6))
* **prover:** add warm rentals and selected-wrapper handoff ([59f509f](https://github.com/syscoin/zksync-airbender-prover/commit/59f509f8e0e4297272648eeb766039862f45c3c4))
* **prover:** add warm rentals and selected-wrapper handoff ([5677fd5](https://github.com/syscoin/zksync-airbender-prover/commit/5677fd5a8cb17840432fa42ed7bd5cf5f7311504))
* **prover:** bind V32 guest and add CPU-cold wrapper lifecycle ([bf05e8e](https://github.com/syscoin/zksync-airbender-prover/commit/bf05e8e0a2e453aae9c69fd358b3eb2d8d0fcad3))
* **prover:** bind V32 guest and opt-in CPU-cold SNARK lifecycle ([1b152e8](https://github.com/syscoin/zksync-airbender-prover/commit/1b152e8f7f2dfd318593574ca8a53a69ee9f36cd))
* **prover:** refresh canonical Syscoin V32 / V8 proving pipeline ([e40b10b](https://github.com/syscoin/zksync-airbender-prover/commit/e40b10b2a1572084981faf35b06bca18ba9845cc))
* **prover:** refresh canonical Syscoin V8 pipeline ([bceccd0](https://github.com/syscoin/zksync-airbender-prover/commit/bceccd0bd7bf30c2449e7b43936b6f5c79c0e3a2))
* **prover:** schedule oldest unassigned jobs across sequencers ([6d74847](https://github.com/syscoin/zksync-airbender-prover/commit/6d74847910b07166dc8e14e8583054ad06941d78))
* Run FRI prover N times and exit ([#50](https://github.com/syscoin/zksync-airbender-prover/issues/50)) ([e6a45e6](https://github.com/syscoin/zksync-airbender-prover/commit/e6a45e6e779626a26d1fe54f4a3d673861d33d79))
* Send protocol version during pick job ([#141](https://github.com/syscoin/zksync-airbender-prover/issues/141)) ([5c96b4f](https://github.com/syscoin/zksync-airbender-prover/commit/5c96b4f1302d6103d527fa8817dbfbf4b5744fa4))
* Sequencer proof client CLI ([#46](https://github.com/syscoin/zksync-airbender-prover/issues/46)) ([d05cb30](https://github.com/syscoin/zksync-airbender-prover/commit/d05cb30197fbdc5078632cd795468d484e0d6731))
* support GPU for snark wrapping ([#47](https://github.com/syscoin/zksync-airbender-prover/issues/47)) ([879257a](https://github.com/syscoin/zksync-airbender-prover/commit/879257a400a943c04d13e25c1831b923198d412f))
* Timeout for http requests ([#91](https://github.com/syscoin/zksync-airbender-prover/issues/91)) ([b1929cd](https://github.com/syscoin/zksync-airbender-prover/commit/b1929cd7b8b7255d197959cface79918d4634081))
* Update prover stack for protocol v1.1 ([#80](https://github.com/syscoin/zksync-airbender-prover/issues/80)) ([c95c4af](https://github.com/syscoin/zksync-airbender-prover/commit/c95c4afcb87ddc6b4e30c7ba649418a9888e254d))
* Update prover stack for protocol v1.2 ([#98](https://github.com/syscoin/zksync-airbender-prover/issues/98)) ([6190921](https://github.com/syscoin/zksync-airbender-prover/commit/619092188f8cf9858c6e9fccf923a3d8197ce5af))
* Update prover stack for protocol v1.3 ([#104](https://github.com/syscoin/zksync-airbender-prover/issues/104)) ([fe5df4d](https://github.com/syscoin/zksync-airbender-prover/commit/fe5df4df5abd644482c9257ecda3a467bfc7c969))
* update prover stack for v31 ([#131](https://github.com/syscoin/zksync-airbender-prover/issues/131)) ([d9733cc](https://github.com/syscoin/zksync-airbender-prover/commit/d9733cc1a6a7b5d1b6638aa371978ffb3ebbbf6d))
* update prover stack for v8  ([#137](https://github.com/syscoin/zksync-airbender-prover/issues/137)) ([f6d4c99](https://github.com/syscoin/zksync-airbender-prover/commit/f6d4c996c6394848476c34508187521a2879e27c))
* Update provers to v1.3.1 ([#115](https://github.com/syscoin/zksync-airbender-prover/issues/115)) ([0d31170](https://github.com/syscoin/zksync-airbender-prover/commit/0d311705c1bf50e97f02cd07b96db593edb768bd))
* Update zksync-os binary to v0.0.25 ([#70](https://github.com/syscoin/zksync-airbender-prover/issues/70)) ([444e80f](https://github.com/syscoin/zksync-airbender-prover/commit/444e80fe332768a299aba0c4d1c61822edad73a1))
* upgrade bincode to v2 ([#32](https://github.com/syscoin/zksync-airbender-prover/issues/32)) ([a206961](https://github.com/syscoin/zksync-airbender-prover/commit/a206961ba5f0ecfc23df8ffac749bd2c9ec4471e))
* V8 program binding, 100-bit proving, zksync-os v0.4.0 binary ([#153](https://github.com/syscoin/zksync-airbender-prover/issues/153)) ([ea89b32](https://github.com/syscoin/zksync-airbender-prover/commit/ea89b3256bc2c1dd6ee8df8ce95cffcdc3eb51ad))
* ZKsync OS prover service ([#62](https://github.com/syscoin/zksync-airbender-prover/issues/62)) ([ad6d04d](https://github.com/syscoin/zksync-airbender-prover/commit/ad6d04d8f8f52bd602f6dd540ac3fe50e1ba3af8))


### Bug Fixes

* Add sequencer URL into error output ([#113](https://github.com/syscoin/zksync-airbender-prover/issues/113)) ([c919e94](https://github.com/syscoin/zksync-airbender-prover/commit/c919e94ebccca2799ba5adab461c29314d57032e))
* Added bellman cuda to snark dockers ([#48](https://github.com/syscoin/zksync-airbender-prover/issues/48)) ([2681bbd](https://github.com/syscoin/zksync-airbender-prover/commit/2681bbd458a81e7e1497cc899399cb9b864d68f5))
* adopt validated optimized Security100 release artifacts ([61ae113](https://github.com/syscoin/zksync-airbender-prover/commit/61ae1133117844d83ec228816b5ed9890da5be91))
* bind canonical-query crypto and regenerated v32 key ([1cb5909](https://github.com/syscoin/zksync-airbender-prover/commit/1cb5909b2da0b52b5a224b2d3236106a7b2b797c))
* bind recursive proof verification to security policy ([c540985](https://github.com/syscoin/zksync-airbender-prover/commit/c540985e189d49d7e64e2dd694540ee70b7a2e04))
* bind Security100 proof verification to trusted policy ([c2fa032](https://github.com/syscoin/zksync-airbender-prover/commit/c2fa032612063eb450c1d9dbb38306bb42cf83b8))
* **build:** avoid full-history proving-source downloads ([699793a](https://github.com/syscoin/zksync-airbender-prover/commit/699793ab6e325bb2ef94910a3402442f58e9b0f9))
* **build:** avoid full-history proving-source downloads ([1c52e75](https://github.com/syscoin/zksync-airbender-prover/commit/1c52e75e621ee2b7235763b92d07c745cc2cf235))
* **build:** consume the pinned common crypto fork ([263005f](https://github.com/syscoin/zksync-airbender-prover/commit/263005fc4212cf2f191438cb67dcabb7bff0eb29))
* **build:** consume the pinned common crypto fork ([8f9d102](https://github.com/syscoin/zksync-airbender-prover/commit/8f9d102bbc7cd7e87e5ecd1c24b3e4783de5964f))
* **build:** keep release tooling imports bytecode-free ([1bbff30](https://github.com/syscoin/zksync-airbender-prover/commit/1bbff305ccc14abe3e03faa0148f0a525d4a2535))
* **build:** reject incompatible historical proving guards before preparation ([4263a73](https://github.com/syscoin/zksync-airbender-prover/commit/4263a735fbac02c5b557c41a6d1f3425482b13dd))
* **build:** reject shallow local source caches before fetch ([ce6d4bd](https://github.com/syscoin/zksync-airbender-prover/commit/ce6d4bd51cbf69162bf5ef1a9c2e29f457726a5c))
* **ci:** derive Airbender overlays from selected source locks ([d4e9407](https://github.com/syscoin/zksync-airbender-prover/commit/d4e94071bb882a696cdf894a9188f8cb1414a4d0))
* **ci:** keep release and SBOM image tags aligned ([a1d2693](https://github.com/syscoin/zksync-airbender-prover/commit/a1d2693536628db5d638066ff5cbd86081fb9a33))
* **ci:** reject incomplete required jobs ([aa4e4e0](https://github.com/syscoin/zksync-airbender-prover/commit/aa4e4e0c41c17fd61b4375db6ab2e7148e7e6f19))
* **ci:** use available fork runner ([7c77b93](https://github.com/syscoin/zksync-airbender-prover/commit/7c77b93599c67b6c1bd0aca75c0cc934c268e072))
* Emit prover metrics ([#77](https://github.com/syscoin/zksync-airbender-prover/issues/77)) ([70deeb9](https://github.com/syscoin/zksync-airbender-prover/commit/70deeb9d602190c960e53ee1cb1697b3b7e0a639))
* Enable full GPU for SNARKer ([#60](https://github.com/syscoin/zksync-airbender-prover/issues/60)) ([dbe2e41](https://github.com/syscoin/zksync-airbender-prover/commit/dbe2e41764fa1d1cdecdfd9044f75efeb6d34f6a))
* Ensure SNARK can't loop forever ([#124](https://github.com/syscoin/zksync-airbender-prover/issues/124)) ([1bfa8ac](https://github.com/syscoin/zksync-airbender-prover/commit/1bfa8ac434883ca97fc987c15a49ae533c89a1bd))
* Fix .dockerignore ([#128](https://github.com/syscoin/zksync-airbender-prover/issues/128)) ([b5d660e](https://github.com/syscoin/zksync-airbender-prover/commit/b5d660e81f5930092028835a46997921f963a11b))
* formatting ([#86](https://github.com/syscoin/zksync-airbender-prover/issues/86)) ([48fd480](https://github.com/syscoin/zksync-airbender-prover/commit/48fd480b74d5710f9f014201f93c20c76864d3df))
* **fri:** bind source degree with transcript-random lift ([00a2c3d](https://github.com/syscoin/zksync-airbender-prover/commit/00a2c3d9ac1930ecdfe54edd7c7c816cf4da29fa))
* **fri:** bind source degree with transcript-random lift ([0217bf6](https://github.com/syscoin/zksync-airbender-prover/commit/0217bf6c56b60752dcea06fc7c0a7241b7d54c28))
* **fri:** pin reviewed Airbender fork for proving ([3033d6c](https://github.com/syscoin/zksync-airbender-prover/commit/3033d6c1ffbce5080d74d7a2eeb11b922ca78834))
* **fri:** preserve zero-opening soundness in degree lift ([51edf5c](https://github.com/syscoin/zksync-airbender-prover/commit/51edf5cf1c457f9ff91b937dbc19272ddd0438a1))
* **fri:** restore source polynomial degree bound ([ac633ef](https://github.com/syscoin/zksync-airbender-prover/commit/ac633ef0dcad77265dca49c86995e86850d0b3eb))
* **gpu:** pass circuit-selected Boojum verification policy ([7e7cdae](https://github.com/syscoin/zksync-airbender-prover/commit/7e7cdae064f8e8adfd8d4f2244fd4b0902cd0ca5))
* **metrics:** include wrapper setup in SNARK latency ([a291c9c](https://github.com/syscoin/zksync-airbender-prover/commit/a291c9c6b673208ccab27c0fdb9e132e842a3ad8))
* Moving init_tracing() to main() ([#72](https://github.com/syscoin/zksync-airbender-prover/issues/72)) ([60b33e2](https://github.com/syscoin/zksync-airbender-prover/commit/60b33e2a738d4b5a6300bad5bf19cf7711ddc792))
* multiblock_batch.bin for v31 ([#133](https://github.com/syscoin/zksync-airbender-prover/issues/133)) ([9c486aa](https://github.com/syscoin/zksync-airbender-prover/commit/9c486aa66d41e1f72311facdf5f30bf941bdfb6e))
* Proper ci runners ([#33](https://github.com/syscoin/zksync-airbender-prover/issues/33)) ([4979714](https://github.com/syscoin/zksync-airbender-prover/commit/4979714f3d87ad7021e16e834753f02a8510a508))
* Properly sanitize credentials in seq URLs ([#109](https://github.com/syscoin/zksync-airbender-prover/issues/109)) ([f84d183](https://github.com/syscoin/zksync-airbender-prover/commit/f84d183eba5cefa5e9f6b7321af685234297851e))
* **prover-service:** apply SNARK acquire timeout only before first job acquisition ([7d2befb](https://github.com/syscoin/zksync-airbender-prover/commit/7d2befb664276ebb5c297d3b38e75a7044640ef8))
* **prover:** align pick capacity and lease outcomes ([c615291](https://github.com/syscoin/zksync-airbender-prover/commit/c61529146e622ecc1d439046769227334c5f6fcd))
* **prover:** compact completed native job inputs ([ab2771e](https://github.com/syscoin/zksync-airbender-prover/commit/ab2771e146b8c71f7180943aa70fddc801949dbd))
* **prover:** drain leased work on shutdown ([be6ddc3](https://github.com/syscoin/zksync-airbender-prover/commit/be6ddc35d33d840bddd78f6c7e48c4ed014e208b))
* **prover:** drop FRI GPU state without unused assignment ([9d671c6](https://github.com/syscoin/zksync-airbender-prover/commit/9d671c6717895509a4b18048990450945db93188))
* **prover:** Ensure round-robin works as intended ([#111](https://github.com/syscoin/zksync-airbender-prover/issues/111)) ([abd5afc](https://github.com/syscoin/zksync-airbender-prover/commit/abd5afc79c9b57d2e1417ebc233d1874cb951c13))
* **prover:** finalize durable v8 handoff and release provenance ([70e4e75](https://github.com/syscoin/zksync-airbender-prover/commit/70e4e75e56d2239d5e981dddf29b0b8dfaf46f41))
* **prover:** gate adaptive SNARK trigger on claimable jobs ([99619db](https://github.com/syscoin/zksync-airbender-prover/commit/99619db7e5efd328293e8fa7c95490d9d8375aba))
* **prover:** harden durable remote handoff ([855c61a](https://github.com/syscoin/zksync-airbender-prover/commit/855c61a987daa642e45c4921d83323f3c59238e3))
* **prover:** harden FlashBoot lifecycle and paired validation ([cc3b26b](https://github.com/syscoin/zksync-airbender-prover/commit/cc3b26b155fe4b4b34611fb56deb89ff4dac91cc))
* **prover:** negotiate bounded 512 MiB SNARK input responses ([8d2c586](https://github.com/syscoin/zksync-airbender-prover/commit/8d2c586becd61b7f7a05d6b05a1c6b417850e695))
* **prover:** publish verification attestations atomically ([bad5b73](https://github.com/syscoin/zksync-airbender-prover/commit/bad5b731766d31f1aec2cf3b59581936f928c562))
* **prover:** reclaim timed-out FRI and SNARK jobs ([0f0cb62](https://github.com/syscoin/zksync-airbender-prover/commit/0f0cb622bc13f1d7d351c3dd616f61d6c95e3758))
* **prover:** reconcile expired Serverless status safely ([fb558c9](https://github.com/syscoin/zksync-airbender-prover/commit/fb558c979a6cf65b9843844ae0ed41fae516899d))
* **prover:** recover interrupted release initialization ([a6ce647](https://github.com/syscoin/zksync-airbender-prover/commit/a6ce6471a73213c5653382c25a1c360eff45edbe))
* **prover:** recover pick initialization and bound warm history ([05d5a16](https://github.com/syscoin/zksync-airbender-prover/commit/05d5a16001cd80f9b30f1c6ab5fac7a45a4e5ac5))
* **prover:** recover pool picks and retire empty probes ([e0752a3](https://github.com/syscoin/zksync-airbender-prover/commit/e0752a374d44cf730ee2de507cb4f87487023203))
* **prover:** recover published verification attestations ([c36a5f7](https://github.com/syscoin/zksync-airbender-prover/commit/c36a5f77abfe22a5c3a821a977ec0574c80c3027))
* **prover:** require multi-FRI jobs on stock Airbender ([f5b33bd](https://github.com/syscoin/zksync-airbender-prover/commit/f5b33bdd46ba04ba6e8382b1420533acea681cd1))
* **prover:** retain guardian ownership until children are reaped ([6cf87da](https://github.com/syscoin/zksync-airbender-prover/commit/6cf87da5cc1bbb2622dfddc6e0505c56f279977c))
* **prover:** reuse FRI caches within rental pods ([21779a8](https://github.com/syscoin/zksync-airbender-prover/commit/21779a87e3579ea1dc64cf1f2ed55a7e05ff120f))
* **prover:** score sequencers by head queue batch ([8b62eea](https://github.com/syscoin/zksync-airbender-prover/commit/8b62eea5c33ef722f5623bb9efac46c6556180ac))
* **prover:** score sequencers by head queue batch ([ad8c558](https://github.com/syscoin/zksync-airbender-prover/commit/ad8c558fa2dbde5872a1add4326c91ceb9d6de69))
* **prover:** stream empty I&T markers and preserve cold commitment policy ([4661d60](https://github.com/syscoin/zksync-airbender-prover/commit/4661d606c6ecd280357f0f1c0e2cf89b8a2f135e))
* **prover:** submit owned work once on shutdown ([2e97545](https://github.com/syscoin/zksync-airbender-prover/commit/2e975453b71962a782ad02ecce04c03a0d32919a))
* **prover:** update transport dependencies and scope bigint advisory ([#19](https://github.com/syscoin/zksync-airbender-prover/issues/19)) ([0acdbdb](https://github.com/syscoin/zksync-airbender-prover/commit/0acdbdb87b9b64d044d7b4abc7f36e29cf4ce49c))
* **prover:** validate combined wrapper before polling ([bb3f0b9](https://github.com/syscoin/zksync-airbender-prover/commit/bb3f0b9c8fdddfb02ee75822485f39e8e452b123))
* Refactor multi_sequencer_proof_client implementation ([#102](https://github.com/syscoin/zksync-airbender-prover/issues/102)) ([f8e5aa4](https://github.com/syscoin/zksync-airbender-prover/commit/f8e5aa49b6edb056828eca2b52a6b1cd949f952d))
* regenerate proving artifacts from canonical guest recipe ([eab93f0](https://github.com/syscoin/zksync-airbender-prover/commit/eab93f0f445d7f3e111d75e71a1bb34781df8164))
* Register metrics ([#75](https://github.com/syscoin/zksync-airbender-prover/issues/75)) ([940610b](https://github.com/syscoin/zksync-airbender-prover/commit/940610b04eb149d596939319a0276c8436e02eb1))
* **release:** bind image SBOMs to immutable build digests ([488f70a](https://github.com/syscoin/zksync-airbender-prover/commit/488f70ac00f8edb74265bae81cd02f3345d359e0))
* **release:** bind image SBOMs to immutable build digests ([5f7c384](https://github.com/syscoin/zksync-airbender-prover/commit/5f7c38421f21ce19bc94596fb00f097b79b16850))
* **release:** bind manual rebuilds to tag source ([562fe28](https://github.com/syscoin/zksync-airbender-prover/commit/562fe28611448188d0e07018ffa103f6093fbd14))
* **release:** bind prover images to verified build inputs ([59be4a0](https://github.com/syscoin/zksync-airbender-prover/commit/59be4a081182b80dd4a4f35e6f41e98d07cb60ed))
* **release:** bind prover images to verified build inputs ([702e234](https://github.com/syscoin/zksync-airbender-prover/commit/702e23402080ee14ecac98fdcad4921d051486d7))
* **release:** bind rebuilds to hardened tooling ([af0dbf0](https://github.com/syscoin/zksync-airbender-prover/commit/af0dbf08c2684d930bed84ccd2ed573933cb9fac))
* **release:** preserve tag refs and separate image tooling source ([3eb7712](https://github.com/syscoin/zksync-airbender-prover/commit/3eb77122e1ce5112efa7617244b9d78dcaeacd30))
* **release:** publish combined prover only with GPU ([471aa96](https://github.com/syscoin/zksync-airbender-prover/commit/471aa96dc2ec21bbf961f4d5b2a34c4378b6ebbb))
* **release:** redirect fork dependencies for historical prover builds ([25f2b62](https://github.com/syscoin/zksync-airbender-prover/commit/25f2b62c699cdfd0d8716ba4f7cf4290304d57ff))
* **release:** use exact release tag commit ([f1680a6](https://github.com/syscoin/zksync-airbender-prover/commit/f1680a61aa8f147094984ed2ad53c91ce30a744e))
* **security:** pin credentialed SBOM tooling to workflow revision ([94bf26a](https://github.com/syscoin/zksync-airbender-prover/commit/94bf26a81237796d33ca1e34646816aecae74c50))
* **snark:** keep test module after library items ([ffa3d75](https://github.com/syscoin/zksync-airbender-prover/commit/ffa3d758a8e9d802b533e784988812bb1ee13c9a))
* **snark:** validate app-bound VK before leasing ([c590c35](https://github.com/syscoin/zksync-airbender-prover/commit/c590c35522dd5be1320fc16127345dd5bb39942d))
* **tls:** refresh prover trust after emSign distrust ([#18](https://github.com/syscoin/zksync-airbender-prover/issues/18)) ([270bdb6](https://github.com/syscoin/zksync-airbender-prover/commit/270bdb691af21307244bbe39b4c861dacc006299))
* update VKs with zksync-os v0.2.4 ([#108](https://github.com/syscoin/zksync-airbender-prover/issues/108)) ([5a6e9b2](https://github.com/syscoin/zksync-airbender-prover/commit/5a6e9b23661388a06b60fcc41d183b38539d3858))
* Upgrade crypto dependencies ([#57](https://github.com/syscoin/zksync-airbender-prover/issues/57)) ([4a87b7f](https://github.com/syscoin/zksync-airbender-prover/commit/4a87b7ff88f2305bec60722a680f90ae4078f602))
* Use correct path to entrypoint.sh ([#54](https://github.com/syscoin/zksync-airbender-prover/issues/54)) ([124cc71](https://github.com/syscoin/zksync-airbender-prover/commit/124cc711930116f5c2841f20aac7e11fff088c85))
* use default headers for Basic Auth ([#114](https://github.com/syscoin/zksync-airbender-prover/issues/114)) ([da9d64b](https://github.com/syscoin/zksync-airbender-prover/commit/da9d64b7fc9872c72361637f7424ec8ca19c6af5))
* widen and simplify prover duration histogram buckets ([#151](https://github.com/syscoin/zksync-airbender-prover/issues/151)) ([43c9fb1](https://github.com/syscoin/zksync-airbender-prover/commit/43c9fb1ded92227c1256531f604fba023a9cefa5))


### Performance Improvements

* **snark:** buffer OS entropy for zero-knowledge padding ([18871be](https://github.com/syscoin/zksync-airbender-prover/commit/18871be4253f74917a9f391127750c2287343ed6))
* **snark:** optimize wrapper padding and bounded batch admission ([0fb06db](https://github.com/syscoin/zksync-airbender-prover/commit/0fb06db8a55111247e4b5f2a39c6754f1638e71d))
* **snark:** optimize zkos-wrapper release builds at level 2 ([980f5e1](https://github.com/syscoin/zksync-airbender-prover/commit/980f5e1866f2b125b026af2dee98125aa592c8c4))

## [0.8.2](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.8.1...v0.8.2) (2026-07-22)


### Features

* Send protocol version during pick job ([#141](https://github.com/matter-labs/zksync-airbender-prover/issues/141)) ([5c96b4f](https://github.com/matter-labs/zksync-airbender-prover/commit/5c96b4f1302d6103d527fa8817dbfbf4b5744fa4))

## [0.8.1](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.8.0...v0.8.1) (2026-05-20)


### Bug Fixes

* multiblock_batch.bin for v31 ([#133](https://github.com/matter-labs/zksync-airbender-prover/issues/133)) ([9c486aa](https://github.com/matter-labs/zksync-airbender-prover/commit/9c486aa66d41e1f72311facdf5f30bf941bdfb6e))

## [0.8.0](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.7.1...v0.8.0) (2026-05-18)


### ⚠ BREAKING CHANGES

* update prover stack for v31 ([#131](https://github.com/matter-labs/zksync-airbender-prover/issues/131))

### Features

* Expose zksync-airbender-prover as image ([#127](https://github.com/matter-labs/zksync-airbender-prover/issues/127)) ([78310c5](https://github.com/matter-labs/zksync-airbender-prover/commit/78310c5434b8c65ac460d6d89ff851146a1eae1e))
* update prover stack for v31 ([#131](https://github.com/matter-labs/zksync-airbender-prover/issues/131)) ([d9733cc](https://github.com/matter-labs/zksync-airbender-prover/commit/d9733cc1a6a7b5d1b6638aa371978ffb3ebbbf6d))


### Bug Fixes

* Ensure SNARK can't loop forever ([#124](https://github.com/matter-labs/zksync-airbender-prover/issues/124)) ([1bfa8ac](https://github.com/matter-labs/zksync-airbender-prover/commit/1bfa8ac434883ca97fc987c15a49ae533c89a1bd))
* Fix .dockerignore ([#128](https://github.com/matter-labs/zksync-airbender-prover/issues/128)) ([b5d660e](https://github.com/matter-labs/zksync-airbender-prover/commit/b5d660e81f5930092028835a46997921f963a11b))

## [0.7.1](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.7.0...v0.7.1) (2026-02-26)


### Features

* add release-bins.yaml ([#118](https://github.com/matter-labs/zksync-airbender-prover/issues/118)) ([f403358](https://github.com/matter-labs/zksync-airbender-prover/commit/f4033580701eb7cfc11d527bc1b6368aa6e068b8))

## [0.7.0](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.6.1...v0.7.0) (2025-12-19)


### ⚠ BREAKING CHANGES

* Update provers to v1.3.1 ([#115](https://github.com/matter-labs/zksync-airbender-prover/issues/115))

### Features

* Centralize timing metrics and improve retry logs ([#107](https://github.com/matter-labs/zksync-airbender-prover/issues/107)) ([ba7b320](https://github.com/matter-labs/zksync-airbender-prover/commit/ba7b320ffa0a3bbc0db3e559f44a28d4d63bcd7f))
* Update provers to v1.3.1 ([#115](https://github.com/matter-labs/zksync-airbender-prover/issues/115)) ([0d31170](https://github.com/matter-labs/zksync-airbender-prover/commit/0d311705c1bf50e97f02cd07b96db593edb768bd))


### Bug Fixes

* Add sequencer URL into error output ([#113](https://github.com/matter-labs/zksync-airbender-prover/issues/113)) ([c919e94](https://github.com/matter-labs/zksync-airbender-prover/commit/c919e94ebccca2799ba5adab461c29314d57032e))
* Properly sanitize credentials in seq URLs ([#109](https://github.com/matter-labs/zksync-airbender-prover/issues/109)) ([f84d183](https://github.com/matter-labs/zksync-airbender-prover/commit/f84d183eba5cefa5e9f6b7321af685234297851e))
* **prover:** Ensure round-robin works as intended ([#111](https://github.com/matter-labs/zksync-airbender-prover/issues/111)) ([abd5afc](https://github.com/matter-labs/zksync-airbender-prover/commit/abd5afc79c9b57d2e1417ebc233d1874cb951c13))
* use default headers for Basic Auth ([#114](https://github.com/matter-labs/zksync-airbender-prover/issues/114)) ([da9d64b](https://github.com/matter-labs/zksync-airbender-prover/commit/da9d64b7fc9872c72361637f7424ec8ca19c6af5))

## [0.6.1](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.6.0...v0.6.1) (2025-11-21)


### Features

* allow passing prover_name in params ([#103](https://github.com/matter-labs/zksync-airbender-prover/issues/103)) ([32f084b](https://github.com/matter-labs/zksync-airbender-prover/commit/32f084bf8a140d14c02fe8e1a5fbcd5df69587be))


### Bug Fixes

* update VKs with zksync-os v0.2.4 ([#108](https://github.com/matter-labs/zksync-airbender-prover/issues/108)) ([5a6e9b2](https://github.com/matter-labs/zksync-airbender-prover/commit/5a6e9b23661388a06b60fcc41d183b38539d3858))

## [0.6.0](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.5.1...v0.6.0) (2025-11-19)


### ⚠ BREAKING CHANGES

* Update prover stack for protocol v1.3 ([#104](https://github.com/matter-labs/zksync-airbender-prover/issues/104))
* Poll a list of sequencers in provers ([#97](https://github.com/matter-labs/zksync-airbender-prover/issues/97))

### Features

* Poll a list of sequencers in provers ([#97](https://github.com/matter-labs/zksync-airbender-prover/issues/97)) ([36b589f](https://github.com/matter-labs/zksync-airbender-prover/commit/36b589f8b041bb82dd86719e626fedd3b9f8c912))
* Update prover stack for protocol v1.3 ([#104](https://github.com/matter-labs/zksync-airbender-prover/issues/104)) ([fe5df4d](https://github.com/matter-labs/zksync-airbender-prover/commit/fe5df4df5abd644482c9257ecda3a467bfc7c969))


### Bug Fixes

* Refactor multi_sequencer_proof_client implementation ([#102](https://github.com/matter-labs/zksync-airbender-prover/issues/102)) ([f8e5aa4](https://github.com/matter-labs/zksync-airbender-prover/commit/f8e5aa49b6edb056828eca2b52a6b1cd949f952d))

## [0.5.1](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.5.0...v0.5.1) (2025-11-06)


### Features

* make Args::disable_zk public ([#99](https://github.com/matter-labs/zksync-airbender-prover/issues/99)) ([299d950](https://github.com/matter-labs/zksync-airbender-prover/commit/299d9504c25293250fc4ec5d14909ee1d9ee56b4))

## [0.5.0](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.4.8...v0.5.0) (2025-11-06)


### ⚠ BREAKING CHANGES

* Update prover stack for protocol v1.2 ([#98](https://github.com/matter-labs/zksync-airbender-prover/issues/98))

### Features

* Add disable_zk flag to CLI ([#95](https://github.com/matter-labs/zksync-airbender-prover/issues/95)) ([4a74a09](https://github.com/matter-labs/zksync-airbender-prover/commit/4a74a0957b59d20e49ab0acd933ac22b878e341a))
* Protocol Upgrade support ([#96](https://github.com/matter-labs/zksync-airbender-prover/issues/96)) ([320a829](https://github.com/matter-labs/zksync-airbender-prover/commit/320a8292adc86100b97db95be7c4cb5624e82d64))
* Timeout for http requests ([#91](https://github.com/matter-labs/zksync-airbender-prover/issues/91)) ([b1929cd](https://github.com/matter-labs/zksync-airbender-prover/commit/b1929cd7b8b7255d197959cface79918d4634081))
* Update prover stack for protocol v1.2 ([#98](https://github.com/matter-labs/zksync-airbender-prover/issues/98)) ([6190921](https://github.com/matter-labs/zksync-airbender-prover/commit/619092188f8cf9858c6e9fccf923a3d8197ce5af))

## [0.4.8](https://github.com/matter-labs/zksync-airbender-prover/compare/v0.4.7...v0.4.8) (2025-10-21)


### Features

* Add ZK to SNARK ([#92](https://github.com/matter-labs/zksync-airbender-prover/issues/92)) ([5c66d6b](https://github.com/matter-labs/zksync-airbender-prover/commit/5c66d6b088322e552da745e2a6925ee15c3fbafb))
* adjust fri prover buckets ([#81](https://github.com/matter-labs/zksync-airbender-prover/issues/81)) ([356bd10](https://github.com/matter-labs/zksync-airbender-prover/commit/356bd1060f0744a5774bb318f94109ac08787196))
* Log unsent SNARK blocks ([#84](https://github.com/matter-labs/zksync-airbender-prover/issues/84)) ([ff3c6fa](https://github.com/matter-labs/zksync-airbender-prover/commit/ff3c6fae52e42eee3c6d9e476b87e2291c29b98a))
* Proof client peek functions ([#85](https://github.com/matter-labs/zksync-airbender-prover/issues/85)) ([a9d8eb7](https://github.com/matter-labs/zksync-airbender-prover/commit/a9d8eb71f74e1da422393d25051190a32147c852))


### Bug Fixes

* formatting ([#86](https://github.com/matter-labs/zksync-airbender-prover/issues/86)) ([48fd480](https://github.com/matter-labs/zksync-airbender-prover/commit/48fd480b74d5710f9f014201f93c20c76864d3df))
