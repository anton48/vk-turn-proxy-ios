import Foundation

enum GeoIPMode: String, Codable, CaseIterable {
    case include
    case exclude

    static func fromProvider(_ value: Any?) throws -> Self {
        guard let value else { return .include }
        guard let raw = value as? String, let mode = Self(rawValue: raw) else {
            throw GeoIPError.invalidDatabase
        }
        return mode
    }

    var label: String {
        switch self {
        case .include: return "Tunnel"
        case .exclude: return "Direct"
        }
    }
}

struct GeoIPSelection: Codable {
    static let settingsKey = "geoIPSelection"
    static let routesKey = "geoip_routes"
    static let modeKey = "geoip_mode"
    static let maxRoutes = 16_384

    let countries: String
    let routes: Data
    let mode: GeoIPMode?

    var routingMode: GeoIPMode { mode ?? .include }

    static func download(countries: String, mode: GeoIPMode) async throws -> Self {
        let tags = Set(countries.uppercased().split {
            $0 == "," || $0.isWhitespace
        }.map(String.init))
        guard !tags.isEmpty, tags.allSatisfy({
            $0.utf8.count == 2 && $0.utf8.allSatisfy { (65...90).contains($0) }
        }) else {
            throw GeoIPError.invalidCountries
        }

        let source = URL(string: "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat")!
        let (file, response) = try await URLSession.shared.download(from: source)
        defer { try? FileManager.default.removeItem(at: file) }
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let size = try file.resourceValues(forKeys: [.fileSizeKey]).fileSize,
              (1...32 * 1024 * 1024).contains(size) else {
            throw GeoIPError.invalidDatabase
        }
        let routes = try resolve(try Data(contentsOf: file, options: .mappedIfSafe), tags: tags)
        return Self(countries: tags.sorted().joined(separator: ", "), routes: routes, mode: mode)
    }

    // Each route is four network address bytes followed by its prefix length.
    static func validRoutes(_ routes: Data) -> Bool {
        guard !routes.isEmpty, routes.count % 5 == 0, routes.count <= maxRoutes * 5 else { return false }
        var previousEnd: UInt64 = 0
        for index in stride(from: routes.startIndex, to: routes.endIndex, by: 5) {
            let length = Int(routes[index + 4])
            guard (1...32).contains(length) else { return false }
            let start = networkAddress(routes, at: index)
            let size = UInt64(1) << (32 - length)
            guard start >= previousEnd, start % size == 0 else { return false }
            previousEnd = start + size
        }
        return true
    }

    // The WireGuard peer must accept every IP that iOS sends into the TUN.
    static func wireGuardCovers(_ routes: Data, uapi: String, mode: GeoIPMode = .include) -> Bool {
        let allowed = uapi.split(separator: "\n").compactMap { line -> UInt64? in
            let key = "allowed_ip="
            guard line.hasPrefix(key) else { return nil }
            let cidr = line.dropFirst(key.count).split(separator: "/", omittingEmptySubsequences: false)
            guard cidr.count == 2, let length = Int(cidr[1]), (0...32).contains(length) else { return nil }
            let parts = cidr[0].split(separator: ".", omittingEmptySubsequences: false)
            let octets = parts.compactMap { UInt8($0) }
            guard parts.count == 4, octets.count == 4 else { return nil }
            let ip = octets.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            let network = length == 0 ? 0 : ip & (UInt32.max << (32 - length))
            return UInt64(network) << 8 | UInt64(length)
        }
        if allowed.contains(0) { return true }
        let coverage = allowed.sorted()
        var candidate = coverage.startIndex

        func covers(_ range: Range<UInt64>) -> Bool {
            var next = range.lowerBound
            while next < range.upperBound, candidate < coverage.endIndex {
                let prefix = coverage[candidate]
                guard prefix >> 8 <= next else { return false }
                let end = prefixEnd(prefix)
                if end >= range.upperBound { return true }
                next = max(next, end)
                candidate += 1
            }
            return next == range.upperBound
        }

        var cursor: UInt64 = 0
        for index in stride(from: routes.startIndex, to: routes.endIndex, by: 5) {
            let start = networkAddress(routes, at: index)
            let end = start + (1 << (32 - Int(routes[index + 4])))
            if mode == .include {
                guard covers(start..<end) else { return false }
            } else {
                guard cursor >= start || covers(cursor..<start) else { return false }
                cursor = max(cursor, end)
            }
        }
        return mode == .include || covers(cursor..<(1 << 32))
    }

    static func resolve(_ database: Data, tags: Set<String>) throws -> Data {
        var remaining = tags
        var prefixes = Set<UInt64>()
        try fields(database) { number, scalar, entry in
            guard number == 1 else { return }
            guard scalar == nil else { throw GeoIPError.invalidDatabase }
            var tag = ""
            var inverse = false
            try fields(entry) { field, value, bytes in
                switch field {
                case 1:
                    guard value == nil else { throw GeoIPError.invalidDatabase }
                    tag = String(decoding: bytes, as: UTF8.self).uppercased()
                case 3:
                    guard let value else { throw GeoIPError.invalidDatabase }
                    inverse = value != 0
                default: break
                }
            }
            guard tags.contains(tag) else { return }
            guard remaining.remove(tag) != nil, !inverse else { throw GeoIPError.invalidDatabase }

            var foundIPv4 = false
            try fields(entry) { field, scalar, cidr in
                guard field == 2 else { return }
                guard scalar == nil else { throw GeoIPError.invalidDatabase }
                var address = Data()
                var length: UInt64 = 0
                try fields(cidr) { field, value, bytes in
                    switch field {
                    case 1:
                        guard value == nil else { throw GeoIPError.invalidDatabase }
                        address = bytes
                    case 2:
                        guard let value else { throw GeoIPError.invalidDatabase }
                        length = value
                    default: break
                    }
                }
                if address.count == 16 && length <= 128 { return }
                guard address.count == 4, (1...32).contains(length) else {
                    throw GeoIPError.invalidDatabase
                }
                let ip = address.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                let network = ip & (UInt32.max << (32 - Int(length)))
                prefixes.insert(UInt64(network) << 8 | length)
                foundIPv4 = true
            }
            guard foundIPv4 else { throw GeoIPError.missingCountry(tag) }
        }
        if let missing = remaining.sorted().first { throw GeoIPError.missingCountry(missing) }
        guard !prefixes.isEmpty else { throw GeoIPError.invalidDatabase }

        let routes = aggregate(prefixes.sorted())
        guard routes.count <= maxRoutes else { throw GeoIPError.tooManyRoutes }
        return Data(routes.flatMap { prefix in
            (0..<5).reversed().map { UInt8(truncatingIfNeeded: prefix >> ($0 * 8)) }
        })
    }

    private static func aggregate(_ prefixes: [UInt64]) -> [UInt64] {
        var routes: [UInt64] = []
        for prefix in prefixes {
            let address = prefix >> 8
            var length = Int(prefix & 0xFF)
            if let last = routes.last, address < prefixEnd(last) { continue }

            var network = address
            while length > 1, let last = routes.last, Int(last & 0xFF) == length {
                let size = UInt64(1) << (32 - length)
                guard network & size != 0, last >> 8 == network - size else { break }
                routes.removeLast()
                network -= size
                length -= 1
            }
            routes.append(network << 8 | UInt64(length))
        }
        return routes
    }

    private static func networkAddress(_ routes: Data, at index: Int) -> UInt64 {
        routes[index..<index + 4].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    private static func prefixEnd(_ prefix: UInt64) -> UInt64 {
        (prefix >> 8) + (1 << (32 - Int(prefix & 0xFF)))
    }

    // V2Ray GeoIPList uses protobuf varints and length-delimited messages.
    private static func fields(_ data: Data, _ visit: (UInt64, UInt64?, Data) throws -> Void) throws {
        var index = data.startIndex

        func varint() throws -> UInt64 {
            var value: UInt64 = 0
            for shift in stride(from: 0, through: 63, by: 7) {
                guard index < data.endIndex else { throw GeoIPError.invalidDatabase }
                let byte = data[index]
                index += 1
                guard shift != 63 || byte <= 1 else { throw GeoIPError.invalidDatabase }
                value |= UInt64(byte & 0x7F) << shift
                if byte < 0x80 { return value }
            }
            throw GeoIPError.invalidDatabase
        }

        while index < data.endIndex {
            let key = try varint()
            let field = key >> 3
            guard field != 0 else { throw GeoIPError.invalidDatabase }
            switch key & 7 {
            case 0:
                try visit(field, varint(), Data())
            case 2:
                let length = try varint()
                guard length <= UInt64(data.endIndex - index) else { throw GeoIPError.invalidDatabase }
                let end = index + Int(length)
                try visit(field, nil, data[index..<end])
                index = end
            default:
                throw GeoIPError.invalidDatabase
            }
        }
    }
}

enum GeoIPError: LocalizedError {
    case invalidCountries
    case invalidDatabase
    case missingCountry(String)
    case tooManyRoutes
    case incompatibleWireGuardRoutes

    var errorDescription: String? {
        switch self {
        case .invalidCountries: return "Enter two-letter country codes, such as RU or CN."
        case .invalidDatabase: return "The GeoIP routing data is invalid."
        case .missingCountry(let country): return "The GeoIP database has no IPv4 networks for \(country)."
        case .tooManyRoutes: return "The selection exceeds the IPv4 route limit. Try a smaller set of countries."
        case .incompatibleWireGuardRoutes: return "The WireGuard profile’s AllowedIPs must cover all IPv4 networks routed through the VPN."
        }
    }
}
