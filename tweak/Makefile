ARCHS = armv7
TARGET = iphone:clang:9.3:6.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LINEBridge
LINEBridge_FILES = Tweak.xm
LINEBridge_FRAMEWORKS = Foundation Security
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
