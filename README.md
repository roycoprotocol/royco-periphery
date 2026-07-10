# Royco Periphery [![CI](https://github.com/roycoprotocol/royco-periphery/actions/workflows/CI.yml/badge.svg)](https://github.com/roycoprotocol/royco-periphery/actions/workflows/CI.yml)

The Royco Periphery is the integration layer around Royco markets: contracts that operate, price, and wrap tranches without belonging to any single structuring substrate. It provides batch NAV accounting synchronization, Chainlink-compatible tranche share price oracles, and Pendle Standardized Yield wrappers, all engineered to work with both **Royco Dawn** and **Royco Day** markets.

## Architecture

### Market Syncer

The **Market Syncer** executes batch NAV accounting synchronization across Royco markets, keeping mark-to-market accounting fresh without waiting for organic deposit and redemption flows. Operators choose per batch whether a failed sync halts the entire batch or is tolerated and recorded as an event carrying the failure reason.

The syncer is an upgradeable, pausable singleton administered through the protocol's access manager. Kernel registration is intentionally unvalidated: it is gated by the access manager, and operators are trusted to supply legitimate kernels.

### Share Price Oracles

Permissionless factories deploy Chainlink-compatible oracles for Royco tranche shares at deterministic addresses. Tranche provenance is intentionally not verified: consumers of an oracle are responsible for vetting the tranche behind it.

**Tranche NAV Oracle**: Prices one whole tranche share in the market's NAV units (USD, BTC, ETH, etc.). If the tranche cannot be valued, the failure reason is passed through to the caller. Because Chainlink consumers reject non-positive prices, the oracle becomes consumable once its tranche has non-zero supply and NAV.

**Tranche Base Asset Oracle**: Prices one whole senior or junior tranche share in the tranche's own base asset for markets whose senior and junior assets are identical, summing the claims on both.

**Fundamental Stablecoin Oracle**: A peg-anchoring wrapper around a stablecoin's fundamental price feed. While the underlying feed reports at or above the minimum pegged price, the wrapper answers exactly one quote asset, suppressing benign oscillation around the peg. Below that threshold, the depegged market price passes through untouched. Round data and staleness carry over from the underlying feed.

### Pendle SY Wrapper

The **Pendle SY** wraps Royco tranche shares into Pendle's Standardized Yield standard, making tranche yield splittable into principal and yield tokens to enable speculating on a tranche's yield. Wrapping and unwrapping are one-to-one with tranche shares, and the exchange rate is the tranche's NAV per share, read identically on both protocols. When granted the tranche's LP role, the SY also accepts the tranche's base asset directly and deposits it into the tranche within the same transaction. Without the grant, it gracefully degrades to wrap-only mode.

Its factory deploys each SY behind a transparent proxy administered by Pendle's canonical proxy admin, with ownership assigned to Pendle's pause controller, per Pendle's deployment requirements.
