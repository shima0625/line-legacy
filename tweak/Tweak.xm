#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <substrate.h>
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

static NSString *const LBPrefsPath = @"/var/mobile/Library/Preferences/jp.naver.line.bridge.plist";
static NSString *const LBStickerMapPath = @"/var/mobile/Library/Caches/jp.naver.line.bridge.stickers.plist";
static NSString *LBBridgeHost = nil;
static BOOL LBEnabled = YES;
static NSData *LBPinnedCertificateSHA256 = nil;
static NSMutableDictionary *LBStickerMap = nil;
static void LBRememberSticker(unsigned int stickerID, long long packageID, unsigned int version);

@interface LineStickerManager : NSObject
+ (id)packageWithID:(long long)packageID version:(unsigned int)version;
@end

static void LBLoadStickerMap(void) {
  NSDictionary *saved = [NSDictionary dictionaryWithContentsOfFile:LBStickerMapPath];
  [LBStickerMap release];
  LBStickerMap = [[NSMutableDictionary alloc] initWithDictionary:(saved ?: @{})];
}

static void LBIndexStrayStickerPackages(void) {
  NSString *root = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/Stray Sticker Packages"];
  NSArray *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:root error:nil];
  for (NSString *entry in entries) {
    NSArray *parts = [entry componentsSeparatedByString:@"."];
    if ([parts count] < 2) continue;
    long long packageID = [[parts objectAtIndex:0] longLongValue];
    unsigned int version = [[parts objectAtIndex:1] unsignedIntValue];
    if (packageID <= 0) continue;
    NSString *path = [[root stringByAppendingPathComponent:entry] stringByAppendingPathComponent:@"productInfo.plist"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:path];
    NSArray *stickers = [info objectForKey:@"stickers"];
    if (![stickers isKindOfClass:[NSArray class]]) continue;
    for (NSDictionary *sticker in stickers) {
      if (![sticker isKindOfClass:[NSDictionary class]]) continue;
      NSNumber *stickerID = [sticker objectForKey:@"id"];
      if ([stickerID unsignedIntValue]) LBRememberSticker([stickerID unsignedIntValue], packageID, version ?: 1);
    }
  }
}

static void LBRememberSticker(unsigned int stickerID, long long packageID, unsigned int version) {
  if (!stickerID || packageID <= 0) return;
  @synchronized(LBStickerMap) {
    NSString *key = [NSString stringWithFormat:@"%u", stickerID];
    [LBStickerMap setObject:@{
      @"package": [NSNumber numberWithLongLong:packageID],
      @"version": [NSNumber numberWithUnsignedInt:(version ?: 1)]
    } forKey:key];
    // Bound the cache without touching LINE's owned-package metadata.
    if ([LBStickerMap count] > 5000) {
      NSArray *keys = [LBStickerMap allKeys];
      NSUInteger removeCount = [LBStickerMap count] - 5000;
      for (NSUInteger i = 0; i < removeCount; i++) [LBStickerMap removeObjectForKey:[keys objectAtIndex:i]];
    }
    [LBStickerMap writeToFile:LBStickerMapPath atomically:YES];
  }
}

%hook LineStickerManager
+ (void)notifySticker:(unsigned int)stickerID existsInPackageWithID:(long long)packageID version:(unsigned int)version {
  %orig;
  LBRememberSticker(stickerID, packageID, version);
}

+ (id)packageWithStickerID:(unsigned int)stickerID {
  id package = %orig;
  if (package || !stickerID) return package;
  NSDictionary *saved = nil;
  @synchronized(LBStickerMap) {
    saved = [[LBStickerMap objectForKey:[NSString stringWithFormat:@"%u", stickerID]] retain];
  }
  if (!saved) {
    // LINE keeps received, non-owned stickers here, but 3.7.1 does not index
    // these packages again after relaunch. Rebuild only the lookup table.
    LBIndexStrayStickerPackages();
    @synchronized(LBStickerMap) {
      saved = [[LBStickerMap objectForKey:[NSString stringWithFormat:@"%u", stickerID]] retain];
    }
  }
  if (!saved) return nil;
  long long packageID = [[saved objectForKey:@"package"] longLongValue];
  unsigned int version = [[saved objectForKey:@"version"] unsignedIntValue];
  [saved release];
  if (packageID <= 0) return nil;
  // Creates an in-memory package used by LineStickerImageSource only. It does
  // not call addActivePackage: and does not mark the package as purchased.
  return [self packageWithID:packageID version:(version ?: 1)];
}
%end

static const char *LBHosts[] = {
  "gd2.line.naver.jp", "legy-jp.line.naver.jp", "t.line.naver.jp",
  "gw.line.naver.jp", "gwx.line.naver.jp", "appresources.line.naver.jp",
  "dl.stickershop.line.naver.jp", "os.line.naver.jp", "dl.os.line.naver.jp",
  "dl.shop.line.naver.jp", "timeline.line.naver.jp", "myhome.line.naver.jp",
  "homeapi.line.naver.jp", "tauth.line.naver.jp", "openapis.jboard.navercorp.jp",
  "cafeapi.line.naver.jp", NULL
};

static BOOL LBIsTarget(const char *host) {
  if (!host || !LBEnabled || !LBBridgeHost.length) return NO;
  for (int i = 0; LBHosts[i]; i++) if (strcasecmp(host, LBHosts[i]) == 0) return YES;
  return NO;
}

static void LBLoadPrefs(void) {
  NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:LBPrefsPath];
  id enabled = [prefs objectForKey:@"enabled"];
  LBEnabled = enabled ? [enabled boolValue] : YES;
  NSString *host = [prefs objectForKey:@"bridge_host"];
  [LBBridgeHost release];
  LBBridgeHost = [(host.length ? host : @"127.0.0.1") copy];
  NSString *fingerprint = [prefs objectForKey:@"certificate_sha256"];
  if (!fingerprint.length) fingerprint = @"";
  fingerprint = [[[fingerprint uppercaseString] componentsSeparatedByCharactersInSet:
    [[NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEF"] invertedSet]] componentsJoinedByString:@""];
  NSMutableData *digest = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
  unsigned char *bytes = (unsigned char *)[digest mutableBytes];
  BOOL valid = fingerprint.length == CC_SHA256_DIGEST_LENGTH * 2;
  for (NSUInteger i = 0; valid && i < CC_SHA256_DIGEST_LENGTH; i++) {
    unsigned int value = 0;
    NSString *pair = [fingerprint substringWithRange:NSMakeRange(i * 2, 2)];
    NSScanner *scanner = [NSScanner scannerWithString:pair];
    valid = [scanner scanHexInt:&value];
    bytes[i] = (unsigned char)value;
  }
  [LBPinnedCertificateSHA256 release];
  LBPinnedCertificateSHA256 = valid ? [digest copy] : nil;
}

static BOOL LBTrustMatchesPin(SecTrustRef trust) {
  if (!LBEnabled || !LBPinnedCertificateSHA256 || !trust || SecTrustGetCertificateCount(trust) < 1) return NO;
  SecCertificateRef certificate = SecTrustGetCertificateAtIndex(trust, 0);
  if (!certificate) return NO;
  CFDataRef certificateData = SecCertificateCopyData(certificate);
  if (!certificateData) return NO;
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(CFDataGetBytePtr(certificateData), (CC_LONG)CFDataGetLength(certificateData), digest);
  CFRelease(certificateData);
  return [LBPinnedCertificateSHA256 isEqualToData:[NSData dataWithBytes:digest length:sizeof(digest)]];
}

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus hook_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
  OSStatus status = orig_SecTrustEvaluate(trust, result);
  if (LBTrustMatchesPin(trust)) {
    if (result) *result = kSecTrustResultProceed;
    NSLog(@"[LINEBridge] accepted pinned bridge certificate");
    return errSecSuccess;
  }
  return status;
}

static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int hook_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result) {
  if (LBIsTarget(node)) {
    NSLog(@"[LINEBridge] %s -> %@", node, LBBridgeHost);
    return orig_getaddrinfo([LBBridgeHost UTF8String], service, hints, result);
  }
  return orig_getaddrinfo(node, service, hints, result);
}

static struct hostent *(*orig_gethostbyname)(const char *);
static struct hostent *hook_gethostbyname(const char *name) {
  if (LBIsTarget(name)) {
    NSLog(@"[LINEBridge] %s -> %@", name, LBBridgeHost);
    return orig_gethostbyname([LBBridgeHost UTF8String]);
  }
  return orig_gethostbyname(name);
}

static CFHostRef (*orig_CFHostCreateWithName)(CFAllocatorRef, CFStringRef);
static CFHostRef hook_CFHostCreateWithName(CFAllocatorRef allocator, CFStringRef hostname) {
  NSString *name = (NSString *)hostname;
  if (name && LBIsTarget([name UTF8String])) {
    NSLog(@"[LINEBridge] CFHost %@ -> %@", name, LBBridgeHost);
    return orig_CFHostCreateWithName(allocator, (CFStringRef)LBBridgeHost);
  }
  return orig_CFHostCreateWithName(allocator, hostname);
}

static void LBPrefsChanged(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
  LBLoadPrefs();
}

%ctor {
  NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
  LBLoadPrefs();
  LBLoadStickerMap();
  LBIndexStrayStickerPackages();
  CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, LBPrefsChanged,
    CFSTR("jp.naver.line.bridge/settingsChanged"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
  MSHookFunction((void *)getaddrinfo, (void *)hook_getaddrinfo, (void **)&orig_getaddrinfo);
  MSHookFunction((void *)gethostbyname, (void *)hook_gethostbyname, (void **)&orig_gethostbyname);
  MSHookFunction((void *)CFHostCreateWithName, (void *)hook_CFHostCreateWithName, (void **)&orig_CFHostCreateWithName);
  MSHookFunction((void *)SecTrustEvaluate, (void *)hook_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);
  [pool drain];
}
