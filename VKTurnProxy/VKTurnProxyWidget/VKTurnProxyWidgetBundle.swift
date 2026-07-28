// VKTurnProxyWidgetBundle.swift
//
// Entry point of the widget extension. Holds only the Live Activity today; an
// ordinary home-screen widget would be added to the same bundle later (that is
// the reason the target exists at all — one extension serves both).
//
// The target's deployment target is 16.1 (the app itself stays on 15.0), so
// nothing in this target needs per-declaration availability annotations.

import SwiftUI
import WidgetKit

@main
struct VKTurnProxyWidgetBundle: WidgetBundle {
    var body: some Widget {
        VPNLiveActivity()
    }
}
