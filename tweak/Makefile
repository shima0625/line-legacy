ARCHS = armv7
TARGET = iphone:clang:9.3:4.3

# 最低OSを5.0未満にすると、clang が /usr/lib/libgcc_s.1.dylib を自動でリンクする。
# iOS 5 以降の端末にこのライブラリは無いので、dyld が読み込みに失敗し、設定画面は
# 「The bundle "LineBridge" couldn't be loaded」、Tweak 本体は無言で無効になる。
# 実際には libgcc_s のシンボルを1つも使っていないので、参照の無い依存を落とさせる。
ADDITIONAL_LDFLAGS = -Wl,-dead_strip_dylibs

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LINEBridge
LINEBridge_FILES = Tweak.xm
LINEBridge_FRAMEWORKS = Foundation Security CFNetwork
LINEBridge_LIBRARIES = substrate

BUNDLE_NAME = LineBridge
LineBridge_FILES = LBRootListController.m
LineBridge_INSTALL_PATH = /Library/PreferenceBundles
LineBridge_FRAMEWORKS = UIKit Foundation
LineBridge_PRIVATE_FRAMEWORKS = Preferences
LineBridge_RESOURCE_DIRS = Resources
LineBridge_CFLAGS = -fno-modules '-DAPI_AVAILABLE(...)='

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/bundle.mk

internal-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences$(ECHO_END)
	$(ECHO_NOTHING)cp LineBridge.entry.plist $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences/LineBridge.plist$(ECHO_END)
