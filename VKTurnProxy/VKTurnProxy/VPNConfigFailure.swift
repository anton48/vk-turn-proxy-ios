// VPNConfigFailure.swift
//
// Decides WHAT to tell the user about a failed VPN-configuration call.
//
// Why this is a separate file
// --------------------------
// This decision has now been got wrong three times, each time in a way a source
// scan could not see: the gate was narrowed, the narrowing looked right in the
// diff, and it silently deleted a branch. `TunnelManager` cannot be compiled by
// the swiftcheck harness (it needs a live NETunnelProviderManager), so a rule
// living there can only ever be checked by grepping its text — which catches a
// missing line and never a wrong verdict. Here it is a pure function over
// (NSError, AppEntitlements), and the harness drives it with fixtures.
// Same reasoning as SpeedTestPathTrace and DirectRouteSync.
//
// What the error actually looks like
// ----------------------------------
// The string a user reports — the bare words "permission denied" — is NOT a
// public NEVPNError case; the public enum has no such code. It originates in the
// internal NEConfigurationErrorDomain (code 10) and reaches the app because
// `+[NEVPNManager mapError:]` re-wraps that error into NEVPNErrorDomain while
// copying `localizedDescription` verbatim. Established by disassembling the
// mapper's jump table in three binaries — the iOS 16.4 and 26.3 simulator
// runtimes and a real iPhone on 26.5.2 from the dyld cache — which agree
// byte-for-byte:
//
//     NEConfigurationError 1,2,3,4,7            -> NEVPNError 1  configurationInvalid
//     NEConfigurationError 5                    -> NEVPNError 4  configurationStale
//     NEConfigurationError 6,8,10,11,12,20,21   -> NEVPNError 5  configurationReadWriteFailed
//     NEConfigurationError 13-19                -> NEVPNError 6  configurationUnknown
//
// 🎯 So the classification needs only PUBLIC constants. Matching the internal
// code 10 would be the wrong design even though we now know the number: it is
// unexported, undocumented, and if Apple ever renumbers it the match fails
// SILENTLY — losing the diagnosis for exactly the population that has no App
// Group and therefore no log to send us.
//
// The direction to fail in
// ------------------------
// 🚨 Attach by default; remove only on a positive match against a documented,
// public code. A false positive lands in the ENTITLED branch, which by
// construction never accuses the signature — it costs the reader three dead-end
// leads. A false negative is silent and unrecoverable in-app. When a new iOS
// invents a code we do not know, the unrecognised path must be the LOUD one.

import Foundation
import NetworkExtension

/// What to add to the framework's own message.
enum VPNFailureAdvice: Equatable {
    /// Add nothing. The framework's description already says what happened and
    /// nothing about signing, MDM or profiles is relevant.
    case plain

    /// Attach `vpnPermissionDiagnosis()`, which branches on the signature itself
    /// — unentitled, entitled, or unreadable.
    case diagnose

    /// A narrower lead: the system rejected a SAVED configuration. Its internal
    /// sources include "configuration owner application is wrong", i.e. a profile
    /// left behind by a differently-signed install — so this must NOT be silently
    /// suppressed, but it also must not talk about entitlements or MDM.
    case savedConfigurationSuspect
}

enum VPNConfigFailure {
    /// The whole rule, as a pure function so the harness can fail a wrong verdict.
    static func classify(_ error: NSError, entitlements: AppEntitlements) -> VPNFailureAdvice {
        // 1. FAMILY. Everything outside NetworkExtension is someone else's failure
        //    — captcha, creds, network, a dead call link — and must never be
        //    blamed on how the app was signed.
        guard error.domain.hasPrefix("NE") else { return .plain }

        // 2. SIGNATURE, decided from OUR OWN binary and never from the error.
        //    A build that cannot run a packet tunnel explains every NE failure it
        //    will ever produce, whatever code carries it. This is the issue-75
        //    path, and it is deliberately independent of any error number so it
        //    cannot stop matching when Apple changes one.
        //    `error == nil` matters: an unreadable signature leaves
        //    hasPacketTunnelProvider false without that meaning anything.
        if entitlements.error == nil && !entitlements.hasPacketTunnelProvider {
            return .diagnose
        }

        // 3. A CONNECTION death is not a CONFIGURATION refusal. `lastDisconnectError`
        //    carries NEVPNConnectionErrorDomain — overslept, no network,
        //    unrecoverable network change, server not responding — none of which
        //    has anything to do with entitlements, MDM or leftover profiles. This
        //    domain was inert until the status observer started reading it; the
        //    moment it did, the fail-open default would have started attaching the
        //    signing leads to every ordinary tunnel drop.
        if #available(iOS 16.0, *), error.domain == NEVPNConnectionErrorDomain {
            return .plain
        }

        // 4. The only suppressors, and only for PUBLIC codes that provably cannot
        //    be a masked permission denial:
        //      · disabled(2) and connectionFailed(3) are never produced by
        //        mapError: at all — they cannot carry a config-layer refusal;
        //      · stale(4) has exactly one internal source, "configuration is
        //        stale", which is a reload, not a refusal.
        //    invalid(1) is NOT suppressed: it is the image of five internal codes
        //    including "configuration owner application is wrong", which is the
        //    leftover-profile case. It gets a narrower message instead.
        if error.domain == NEVPNErrorDomain,
           let code = NEVPNError.Code(rawValue: error.code) {
            switch code {
            case .configurationDisabled, .connectionFailed, .configurationStale:
                return .plain
            case .configurationInvalid:
                return .savedConfigurationSuspect
            default:
                break
            }
        }

        // 5. Everything else — readWriteFailed(5), which is where "permission
        //    denied" lands, configurationUnknown(6), a code this build has never
        //    heard of, or another NE-family domain. Loud by default.
        return .diagnose
    }

    /// Whether a failed save means "the configuration you are holding is out of
    /// date" — the one failure a retry can actually fix.
    ///
    /// `configurationStale` says it outright: something else changed the profile
    /// since we loaded it, so the object we are writing is a dead generation.
    /// `configurationInvalid` reaches us from five internal codes and one of them
    /// is the same situation (a profile owned by another install), so it is worth
    /// one reload as well — this is also the pair WireGuard-apple guards on in
    /// `startActivation`.
    ///
    /// 🚨 Retrying the SAME write cannot fix either: what must change is the
    /// generation we are writing against, which is why the caller reloads before
    /// trying again.
    static func isStaleConfiguration(_ error: NSError) -> Bool {
        guard error.domain == NEVPNErrorDomain,
              let code = NEVPNError.Code(rawValue: error.code) else { return false }
        return code == .configurationStale || code == .configurationInvalid
    }
}
