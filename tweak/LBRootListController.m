#import <Foundation/Foundation.h>

// iOS 5.1 SDK には NS_ENUM が無い(iOS 6 SDK から)。Theos 同梱の Preferences
// ヘッダがこれを使うので、無いときだけ同じ意味の定義を補う。
#ifndef NS_ENUM
#define NS_ENUM(_type, _name) enum _name : _type _name; enum _name : _type
#endif

#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import <UIKit/UIKit.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// 母艦の /bridge/config へ HTTP で問い合わせ、ステータスコードを返す(失敗は 0)。
// NSURLConnection を使わずソケットで直接送る。iOS 9 以降の設定アプリの中では
// App Transport Security が http:// を拒否しうるが、ソケットはその対象外。
// あわせて、iOS のバージョンでクラスの置き場所が変わる問題とも無縁になる。
static int LBProbeBridge(NSString *host, NSString **reason) {
  struct addrinfo hints, *result = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int gai = getaddrinfo([host UTF8String], "8081", &hints, &result);
  if (gai != 0 || !result) {
    *reason = [NSString stringWithUTF8String:gai_strerror(gai)];
    return 0;
  }
  int status = 0;
  *reason = @"応答なし";
  for (struct addrinfo *ai = result; ai && !status; ai = ai->ai_next) {
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int connected = connect(fd, ai->ai_addr, ai->ai_addrlen) == 0;
    if (!connected && errno == EINPROGRESS) {
      struct pollfd pfd = { fd, POLLOUT, 0 };
      int error = 0;
      socklen_t length = sizeof(error);
      connected = poll(&pfd, 1, 5000) == 1
        && getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0;
      if (!connected) errno = error ?: ETIMEDOUT;
    }
    if (!connected) {
      *reason = [NSString stringWithUTF8String:strerror(errno)];
      close(fd);
      continue;
    }
    fcntl(fd, F_SETFL, flags);
    struct timeval timeout = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    const char *request = [[NSString stringWithFormat:@"GET /bridge/config HTTP/1.0\r\nHost: %@\r\n\r\n", host] UTF8String];
    char response[64];
    ssize_t received = -1;
    if (send(fd, request, strlen(request), 0) >= 0) {
      received = recv(fd, response, sizeof(response) - 1, 0);
    }
    if (received > 0) {
      response[received] = '\0';
      if (sscanf(response, "HTTP/%*d.%*d %d", &status) != 1) status = 0;
    }
    close(fd);
  }
  freeaddrinfo(result);
  return status;
}

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
  NSString *reason = nil;
  int code = LBProbeBridge(host, &reason);
  NSString *message = (code >= 200 && code < 500) ? @"サーバーへ接続できました" : [NSString stringWithFormat:@"接続できません\n%@", reason];
  [[[[UIAlertView alloc] initWithTitle:@"LINE Bridge" message:message delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil] autorelease] show];
}

- (void)applySettings {
  CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("jp.naver.line.bridge/settingsChanged"), NULL, NULL, YES);
  system("killall LINE >/dev/null 2>&1");
  [[[[UIAlertView alloc] initWithTitle:@"LINE Bridge" message:@"保存しました。次回のLINE起動から反映されます。" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil] autorelease] show];
}
@end
