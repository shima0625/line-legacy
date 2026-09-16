ARCHS = armv7
# 対応する中で一番古い世代の SDK でビルドする。新しい SDK には「古い iOS ではクラスが
# 別のライブラリにあった」という情報が無く、iOS 9.3 SDK だとリンカが NSObject を
# libobjc に、NSURLConnection を CFNetwork に結び付けた。iOS 5 ではそれぞれ
# CoreFoundation と Foundation にあるため、設定画面が
# 「The bundle "LineBridge" couldn't be loaded」で開けなかった。古い SDK で
# ビルドしたものは、新しい iOS が互換のために読み込める。
# SDK は theos/sdks/iPhoneOS5.1.sdk に置く(README を参照)。
TARGET = iphone:clang:5.1:4.3

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
