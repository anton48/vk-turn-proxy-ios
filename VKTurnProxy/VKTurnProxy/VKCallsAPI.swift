import Foundation

/// `calls.start` — create a VK call from the user's own account.
///
/// Why this exists: since ~2026-08-03 VK ends a call the moment the person who
/// created it in a browser leaves, so a link made today dies immediately and
/// the app then gets "Call not found" (GitHub issue #69). Older links are
/// unaffected. A call started through the API survives with nobody in it, so
/// this is the way to mint a link that keeps working.
enum VKCallsAPI {
    /// VK API version. Pinned rather than tracking latest — a version bump is
    /// a deliberate act here, the same as everywhere else in this app.
    static let apiVersion = "5.276"

    /// vk.ru first (the whole app has moved there), vk.com as the fallback:
    /// the migration is not finished and the one verified-by-hand run used
    /// vk.com. A VK-level error is a real ANSWER and stops the walk; only a
    /// transport failure moves to the next host.
    static let hosts = ["api.vk.ru", "api.vk.com"]

    struct Created {
        /// The join link exactly as VK returned it — NOT rewritten. Which
        /// domain comes back is not ours to predict: a hand-run curl on
        /// 2026-08-05 got a vk.com link, the first on-device run the same day
        /// got vk.ru. Both the Swift parser (BackupManager.stripVkUrl) and the
        /// Go one accept either, so passing the link through untouched is both
        /// simpler and safer than normalising a link that already works.
        let joinLink: String
    }

    enum Failure: Error {
        /// VK answered, and said no. Carries VK's own wording — the user is
        /// better served by "Group authorization failed…" than by ours.
        case vk(code: Int, message: String)
        case transport(String)
        case malformed

        var userMessage: String {
            switch self {
            case let .vk(code, message): return "VK error \(code): \(message)"
            case let .transport(m): return "Network error: \(m)"
            case .malformed: return "VK returned an unexpected response."
            }
        }
    }

    /// Create a call. The token is used and forgotten — it is never stored,
    /// never logged, and never leaves this call.
    static func startCall(accessToken: String) async -> Result<Created, Failure> {
        var lastTransport: Failure = .transport("no hosts tried")

        for host in hosts {
            var comps = URLComponents()
            comps.scheme = "https"
            comps.host = host
            comps.path = "/method/calls.start"
            comps.queryItems = [
                URLQueryItem(name: "v", value: apiVersion),
                URLQueryItem(name: "access_token", value: accessToken),
            ]
            guard let url = comps.url else { return .failure(.malformed) }

            var req = URLRequest(url: url)
            req.httpMethod = "GET"
            req.timeoutInterval = 20

            do {
                let (data, _) = try await URLSession.shared.data(for: req)
                guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    return .failure(.malformed)
                }
                if let err = obj["error"] as? [String: Any] {
                    let code = err["error_code"] as? Int ?? -1
                    let msg = err["error_msg"] as? String ?? "unknown error"
                    SharedLogger.shared.log("[vk-calls] calls.start on \(host) → VK error \(code)")
                    return .failure(.vk(code: code, message: msg))
                }
                guard let resp = obj["response"] as? [String: Any],
                      let link = resp["join_link"] as? String, !link.isEmpty else {
                    SharedLogger.shared.log("[vk-calls] calls.start on \(host) → no join_link in response")
                    return .failure(.malformed)
                }
                SharedLogger.shared.log("[vk-calls] call created via \(host)")
                return .success(Created(joinLink: link))
            } catch {
                SharedLogger.shared.log("[vk-calls] calls.start on \(host) failed: \(error.localizedDescription)")
                lastTransport = .transport(error.localizedDescription)
                continue
            }
        }
        return .failure(lastTransport)
    }
}
