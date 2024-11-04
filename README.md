# MCTDroid: Evading Android Malware Detection via Monte-Carlo Tree Search in Zero-Knowledge Settings

## Abstract

The widespread use of Android has made its apps a prime target for cyber attackers. To combat this, detecting malware on Android using machine learning (ML-based AMD) is crucial. However, these methods struggle against adversarial examples, raising significant concerns. Current attacks on ML-based AMD are sophisticated but often rely on unrealistic assumptions about the attacker's knowledge of the system. To address this, we introduce MCTDroid, a novel method that employs the Monte Carlo Tree Search (MCTS) algorithm alongside a curated Malware Perturbation Selection Pool. This method strategically generates adversarial malware through a process of selection, expansion, simulation, and backpropagation, effectively evading detection. Tested on public datasets, MCTDroid outperforms existing techniques, offering a more effective way to bypass malware detection.

## Disclaimer
This repository is intended solely for academic research and records the relevant code for constructing adversarial samples for Android using Monte Carlo Tree. The implementation of the perturbation selection pool part refers to the article "[AdvDroidZero](https://github.com/gnipping/AdvDroidZero-Access-Instructions)" from CCS 2023. At present, only the main attack logic has been implemented, and comparative experiments on attack effects, cost analysis, etc., are still in progress：）

