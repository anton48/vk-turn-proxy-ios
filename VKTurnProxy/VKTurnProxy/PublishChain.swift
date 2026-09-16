// PublishChain.swift
//
// The Live Activity's publishes to ActivityKit, in the order they were
// produced, with a wait that means something.
//
// 🚨 EVERY publish is a link — an update AND an end. The controller chained
// its updates so ActivityKit received them in order and so that awaiting the
// newest link awaited every link behind it; its end() still ran in a Task of
// its own, outside the chain. So `refreshNowAndWait()` returned while
// `Activity.end` was pending — and a Live Activity intent's process is
// suspended the moment perform() returns, so a card the app had "ended" stayed
// on screen (the user's stand on 404, ActivityKit substituted: "selectServer
// handler returned=true, Activity.end completed=false"). One chain for both,
// and the wait is the newest link's completion.
//
// Foundation-only, so the harness can drive it: a gated link holds the wait,
// and two links run in the order they were appended.

import Foundation

struct PublishChain {
    private var last: Task<Void, Never>?
    /// Links appended so far.
    private(set) var count = 0

    /// Append a publish. It runs after every link before it, whatever it does.
    mutating func append(_ work: @escaping @Sendable () async -> Void) {
        let previous = last
        last = Task {
            await previous?.value
            await work()
        }
        count += 1
    }

    /// Returns once every link appended so far has completed.
    func wait() async {
        await last?.value
    }
}
