BUILDDIR ?= $(CURDIR)/build
DESTDIR ?= $(BUILDDIR)

# iOS SDK paths
IOS_SDK := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
IOS_SIM_SDK := $(shell xcrun --sdk iphonesimulator --show-sdk-path 2>/dev/null)
IOS_MIN_VERSION := 15.0

# Go settings
export CGO_ENABLED := 1
export GOARCH := arm64

GO_BUILD_FLAGS := -buildmode=c-archive -trimpath -tags ios
GO_LDFLAGS := -s -w

# Patched GOROOT: replaces mach_absolute_time with mach_continuous_time
# so that Go timers keep ticking while the iOS device is asleep.
REAL_GOROOT := $(shell go env GOROOT 2>/dev/null)
PATCHED_GOROOT := $(BUILDDIR)/goroot

.PHONY: all clean ios-device ios-simulator xcframework goroot

all: xcframework

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Create a patched copy of GOROOT with boottime monotonic clock
goroot: $(BUILDDIR)
	@if [ ! -f "$(PATCHED_GOROOT)/.patched" ]; then \
		echo "==> Creating patched GOROOT (boottime monotonic clock)..."; \
		rm -rf "$(PATCHED_GOROOT)"; \
		mkdir -p "$(PATCHED_GOROOT)"; \
		rsync -a --delete --exclude=pkg/obj/go-build "$(REAL_GOROOT)/" "$(PATCHED_GOROOT)/"; \
		cd "$(PATCHED_GOROOT)" && patch -p1 -f -N -r- < "$(CURDIR)/goruntime-boottime-over-monotonic.diff"; \
		touch "$(PATCHED_GOROOT)/.patched"; \
		echo "==> GOROOT patched successfully"; \
	else \
		echo "==> Using cached patched GOROOT"; \
	fi

# Build for iOS device (arm64)
# CRITICAL: GOOS=ios (not darwin!) enables iOS-specific signal handling
# in the Go runtime, preventing "non-Go code disabled sigaltstack" crashes
# in Network Extension threads.
ios-device: goroot
	@echo "==> Building for iOS device (arm64) with GOOS=ios..."
	GOROOT="$(PATCHED_GOROOT)" \
	CGO_CFLAGS="-isysroot $(IOS_SDK) -arch arm64 -miphoneos-version-min=$(IOS_MIN_VERSION)" \
	CGO_LDFLAGS="-isysroot $(IOS_SDK) -arch arm64 -miphoneos-version-min=$(IOS_MIN_VERSION)" \
	GOARCH=arm64 \
	GOOS=ios \
	CGO_ENABLED=1 \
	CC="$(shell xcrun --sdk iphoneos -f clang) -isysroot $(IOS_SDK) -arch arm64 -miphoneos-version-min=$(IOS_MIN_VERSION)" \
	go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o $(BUILDDIR)/libwg-turn-ios-arm64.a .
	@echo "==> Done: $(BUILDDIR)/libwg-turn-ios-arm64.a"

# Build for iOS Simulator (arm64 for Apple Silicon)
ios-simulator: goroot
	@echo "==> Building for iOS Simulator (arm64)..."
	GOROOT="$(PATCHED_GOROOT)" \
	CGO_CFLAGS="-isysroot $(IOS_SIM_SDK) -arch arm64 -miphonesimulator-version-min=$(IOS_MIN_VERSION)" \
	CGO_LDFLAGS="-isysroot $(IOS_SIM_SDK) -arch arm64 -miphonesimulator-version-min=$(IOS_MIN_VERSION)" \
	GOARCH=arm64 \
	GOOS=ios \
	CGO_ENABLED=1 \
	CC="$(shell xcrun --sdk iphonesimulator -f clang) -isysroot $(IOS_SIM_SDK) -arch arm64 -miphonesimulator-version-min=$(IOS_MIN_VERSION)" \
	go build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o $(BUILDDIR)/libwg-turn-sim-arm64.a .
	@echo "==> Done: $(BUILDDIR)/libwg-turn-sim-arm64.a"

# Create XCFramework from both architectures
xcframework: ios-device ios-simulator
	@echo "==> Creating XCFramework..."
	rm -rf $(DESTDIR)/WireGuardTURN.xcframework
	xcodebuild -create-xcframework \
		-library $(BUILDDIR)/libwg-turn-ios-arm64.a -headers $(CURDIR)/include \
		-library $(BUILDDIR)/libwg-turn-sim-arm64.a -headers $(CURDIR)/include \
		-output $(DESTDIR)/WireGuardTURN.xcframework
	@echo "==> Done: $(DESTDIR)/WireGuardTURN.xcframework"

clean:
	rm -rf $(BUILDDIR)
	rm -rf $(DESTDIR)/WireGuardTURN.xcframework
