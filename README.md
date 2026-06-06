<div align="center">
<h1>PMPatch</h1>

![downloads](https://img.shields.io/github/downloads/vova7878-modules/PMPatch/total)
[![GitHub release](https://img.shields.io/github/v/release/vova7878-modules/PMPatch)](https://github.com/vova7878-modules/PMPatch/releases)
[![4PDA](https://img.shields.io/badge/4PDA-Topic-blue)](https://4pda.to/forum/index.php?showtopic=915158&view=findpost&p=134245253)

<p>Disable signature verification for Android</p>
</div>

### Changes from upstream:

- Updated upstream dependencies to adapted to new version `com.android.art`. Special thanks to vova78; this project depends on his excellent hook framework foundation.
- Added more hook coverage, allowing PMPatch to achieve part of the previous Patch 12 goals.
- Restricted PM signature hooks to install paths on top of that coverage, reducing package-manager anomalies reported by banking apps and root detectors.
- Small performance optimization.

### 12 vs. 3 vs. Full:

- Patch 12 works at the lower digest / crypto / SSL library level and is meant for installing unsigned high-privilege packages (Modded Play Store). Because this affects global signature comparison, banking apps and root detectors are very likely to report the device as insecure.
- Patch 3 focuses on package installation behavior such as downgrade, signature mismatch, unsigned APKs, and related install-time verification paths, while trying to avoid global signature comparison changes.
- Full combines Patch 12 and Patch 3.

Because Patch 3 can now achieve part of the old Patch 12 goals with a safer scope, this repository currently does not continue to provide Patch 12 or Full builds.

### Technical requirements:

- Android 8-16 and any of the Zygisk options for Magisk / APatch / KernelSU
