import SwiftUI
import UIKit

/// Tapping empty space should dismiss the keyboard, same as almost every
/// other iOS app. SwiftUI's Form/List swallow a plain `.onTapGesture` placed
/// on their background before it ever reaches the gaps between rows, so a
/// per-screen modifier doesn't work here. This installs ONE
/// UITapGestureRecognizer directly on the window instead — outside SwiftUI's
/// hit-testing entirely — with `cancelsTouchesInView = false` so it never
/// blocks a button, row tap, or anything else already listening; it only
/// ever adds "also resign the keyboard" on top of whatever that tap already
/// does.
///
/// An earlier version of this file was reverted after the keyboard stopped
/// appearing at all in testing. Root cause turned out to be unrelated:
/// stale iOS Simulator state (fixed by Simulator → Device → Erase All
/// Content and Settings) — confirmed by the SAME failure reproducing on a
/// completely clean checkout with none of this code present. Restored, and
/// this paragraph is the ONE account of that episode: do not re-add the
/// "UIKit tap gesture broke focus" reading elsewhere, it was the simulator.
///
/// Device-verified 2026-08-07 (iPhone SE3) against the case that looks most
/// dangerous — typing inside a WKWebView, i.e. the VK login and the VK ID
/// screens, where losing focus mid-form would break the cookie auth the app
/// depends on. It is not affected, and the reason is structural rather than
/// lucky: in a WKWebView the first responder is the WKContentView, whose
/// bounds span the whole page, so every tap on web content is INSIDE the
/// responder and `shouldReceive` declines the gesture. The recognizer can
/// only fire outside the web view — e.g. on the sheet's own header — where
/// dismissing is what you want anyway.

/// Standard "find the current first responder" trick — UIResponder exposes
/// no direct API for it, so this asks the responder chain itself: `sendAction`
/// with a nil target routes to whatever IS first responder, which records
/// itself here.
private extension UIResponder {
    private static weak var _currentFirstResponder: UIResponder?

    static var currentFirstResponder: UIResponder? {
        _currentFirstResponder = nil
        UIApplication.shared.sendAction(#selector(captureFirstResponder), to: nil, from: nil, for: nil)
        return _currentFirstResponder
    }

    @objc private func captureFirstResponder() {
        UIResponder._currentFirstResponder = self
    }
}

/// Gesture recognizers do not retain their target, so this needs to live for
/// the app's lifetime — a singleton does that.
///
/// The delegate check runs at touch-DOWN, i.e. before this tap could have
/// changed focus yet, so "the current first responder" here really means
/// "what was focused before this tap":
///   - nothing focused yet → nothing to dismiss → don't even recognize the
///     gesture. This is what makes tapping a field for the first time safe:
///     our recognizer stays out of it entirely, so it cannot race the
///     field's own focus-gain.
///   - something IS focused and this tap lands OUTSIDE its bounds (empty
///     row space, a different field, a button, ...) → recognize, and
///     `handleTap` resigns it. cancelsTouchesInView = false means the touch
///     still reaches whatever was actually tapped afterward — a tap on a
///     DIFFERENT field still focuses that field normally; iOS already
///     resigns the old responder as part of that regardless of us.
///   - something focused and the tap is INSIDE its own bounds (repositioning
///     the cursor in the field you're already editing) → don't recognize,
///     don't interrupt.
private final class KeyboardDismissTarget: NSObject, UIGestureRecognizerDelegate {
    static let shared = KeyboardDismissTarget()

    @objc func handleTap(_ sender: UITapGestureRecognizer) {
        sender.view?.endEditing(true)
    }

    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldReceive touch: UITouch) -> Bool {
        guard let responderView = UIResponder.currentFirstResponder as? UIView else { return false }
        let point = touch.location(in: responderView)
        return !responderView.bounds.contains(point)
    }
}

/// Finds its own window via `didMoveToWindow` and wires the gesture to it
/// exactly once (guarded by `name` so re-mounting this invisible view, e.g.
/// on a scene change, never stacks up duplicate recognizers).
private final class KeyboardDismissAnchor: UIView {
    override func didMoveToWindow() {
        super.didMoveToWindow()
        guard let window,
              window.gestureRecognizers?.contains(where: { $0.name == "keyboardDismiss" }) != true
        else { return }
        let tap = UITapGestureRecognizer(
            target: KeyboardDismissTarget.shared,
            action: #selector(KeyboardDismissTarget.handleTap(_:))
        )
        tap.name = "keyboardDismiss"
        tap.cancelsTouchesInView = false
        tap.delegate = KeyboardDismissTarget.shared
        window.addGestureRecognizer(tap)
    }
}

/// SwiftUI wrapper for `KeyboardDismissAnchor`. Attach once, at the
/// WindowGroup root — every screen shares the same window, so one instance
/// covers the whole app (main screen, Settings, ServerEditView, ...).
struct KeyboardDismisser: UIViewRepresentable {
    func makeUIView(context: Context) -> UIView { KeyboardDismissAnchor(frame: .zero) }
    func updateUIView(_ uiView: UIView, context: Context) {}
}
