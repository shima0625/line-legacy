#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import <UIKit/UIKit.h>
#include <stdlib.h>

@interface LBRootListController : PSListController
@end

@implementation LBRootListController
- (NSArray *)specifiers {
  if (!_specifiers) _specifiers = [[self loadSpecifiersFromPlistName:@"Root" target:self] retain];
  return _specifiers;
}

- (void)testConnection {
  NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/jp.naver.line.bridge.plist"];
  NSString *host = [prefs objectForKey:@"bridge_host"] ?: @"127.0.0.1";
  NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"http://%@:8081/bridge/config", host]];
  NSURLResponse *response = nil;
  NSError *error = nil;
  [NSURLConnection sendSynchronousRequest:[NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:5.0]
    returningResponse:&response error:&error];
  NSInteger code = [(NSHTTPURLResponse *)response statusCode];
  NSString *message = (!error && code >= 200 && code < 500) ? @"サーバーへ接続できました" : [NSString stringWithFormat:@"接続できません\n%@", error.localizedDescription ?: @"応答なし"];
  [[[[UIAlertView alloc] initWithTitle:@"LINE Bridge" message:message delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil] autorelease] show];
}

- (void)applySettings {
  CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("jp.naver.line.bridge/settingsChanged"), NULL, NULL, YES);
  system("killall LINE >/dev/null 2>&1");
  [[[[UIAlertView alloc] initWithTitle:@"LINE Bridge" message:@"保存しました。次回のLINE起動から反映されます。" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil] autorelease] show];
}
@end
