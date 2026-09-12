# LINE Legacy compatibility gateway

LINE for iOS 3.7.1を、現在のLINEサービスへ接続するための非公式な互換ゲートウェイです。所有している旧端末・検証用アカウントでの研究用途を想定しています。

LINEおよびLY Corporationの公式ソフトウェアではありません。

## 現在の対応範囲

- QRログインしたLINEJSセッションを利用したメッセージ送受信
- テキスト、スタンプ、画像、動画、音声の送受信
- 自分が別端末から送信したメッセージの表示
- プロフィール、友だち、非表示、ブロック、ブロック解除
- グループ一覧、メンバー名・アイコン、招待・退出・名称変更など
- 「知り合いかも？」の取得（友だち一覧とは分離）
- ホーム／タイムライン、ノート、コメント、返信、いいね
- お知らせを公式Webページへ接続
- スタンプショップ互換応答と旧CDN URL変換
- メディアのRange配信、動画サムネイル、E2EE動画ワーカー
- 3.7.1での発信・着信通話（EAS1コーデックヘルパーが別途必要。下記参照）
- 相手側で付いた既読の3.7.1への反映
- 位置情報・連絡先の送信
- 新着メッセージと着信のプッシュ通知（Skyglowサーバーが別途必要。下記参照）
- iOS 5以上／armv7用LINEBridge Tweak（接続先変更、証明書ピン留め、受信済み非所持スタンプの再起動後復元）

タイムラインは既定でフォロー中の投稿だけを表示します。VOOMのおすすめ投稿も不足分へ混ぜたい場合だけ、`TIMELINE_INCLUDE_RECOMMENDED=1`を設定してください。

## 対応しないもの・制限

- ファイル送信（クライアント側への搭載はLINE 5.3.0以降のため対象外）
- グループ通話（LINE 3.7.1自体に機能がありません）
- Tweakを使わずに、非所持の受信スタンプを再起動後も表示する処理
- **このゲートウェイ同士の通話**（両端が本ブリッジのとき、PLANETのメディア鍵が噛み合わず、双方の声がノイズになります。相手が通常のLINEクライアントであれば問題ありません）

非所持スタンプ復元機能は、LINE自身が保存した受信スタンプ用キャッシュを起動時に再読込します。パッケージを購入済み・使用可能として登録せず、所持スタンプ一覧にも追加しません。

## 全体像

```text
iPhone (iOS 5/6 + LINE 3.7.1 + LINEBridge Tweak)
        │  LAN: TCP 80 / 443 / 8081
        ▼
Ubuntu母艦 (LINE Legacy gateway)
        │  LINEJSセッション
        ▼
     現行LINE
```

TweakがLINEアプリ内の接続先を母艦へ向け、母艦が新旧プロトコルを変換します。Tweakを使う通常構成では、iPhoneのDNSや`/etc/hosts`は変更しません。`line-legacy-dns.service`はTweakを使わない検証用の代替手段で、既定では起動しません。

## Ubuntuへのセットアップ

以下は、iPhoneと同じLAN上のUbuntuを母艦にする手順です。`192.168.1.10`は母艦のLAN IP、`192.168.1.20`はiPhoneのLAN IPの例です。実際の値に読み替えてください。

### 1. 必要なソフトを入れる

```sh
sudo apt update
sudo apt install -y git curl python3 python3-venv nodejs npm ffmpeg apache2 patch openssl
git clone https://github.com/shima0625/line-legacy.git
cd line-legacy
```

Node.js 20以上を推奨します。`node --version`で確認し、Ubuntu付属版が古い場合はNode.jsの公式配布版を使ってください。

### 2. ゲートウェイを配置する

```sh
sudo ./tools/install-files.sh
sudo python3 -m venv /opt/line-legacy/venv
sudo /opt/line-legacy/venv/bin/pip install -r /opt/line-legacy/requirements.txt
sudo -u linelegacy sh -c 'cd /opt/line-legacy/linejs-bridge && npm install'
sudo /opt/line-legacy/tools/patch-linejs.sh
```

`install-files.sh`は専用ユーザー`linelegacy`、実行ファイル、systemdユニット、Apacheの80番転送設定を用意します。この時点ではサービスは起動しません。`patch-linejs.sh`は通話、通話応答のトランザクションID、音声メッセージの長さをまとめて修正します。`npm install`の後に1回実行してください。

### 3. TLS証明書を作る

```sh
sudo openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -subj '/CN=LINE Legacy Bridge' \
  -keyout /etc/line-legacy/server.key \
  -out /etc/line-legacy/server.crt
sudo sh -c 'cat /etc/line-legacy/server.key /etc/line-legacy/server.crt > /etc/line-legacy/server.pem'
sudo chown root:linelegacy /etc/line-legacy/server.key /etc/line-legacy/server.crt /etc/line-legacy/server.pem
sudo chmod 640 /etc/line-legacy/server.key /etc/line-legacy/server.crt /etc/line-legacy/server.pem
sudo openssl x509 -in /etc/line-legacy/server.crt -noout -fingerprint -sha256
```

最後に出る`SHA256 Fingerprint=...`の値を控えます。コロン付きのままTweakに入力できます。

### 4. 環境のアドレスを設定する

```sh
sudo nano /etc/line-legacy/line-legacy.env
```

通常のメッセージ送受信では、次の2値を母艦のLAN IPに合わせます。

```ini
LINE_LEGACY_SERVER_IP=192.168.1.10
LINE_LEGACY_MEDIA_BASE=http://192.168.1.10:8081
```

通話も使う場合は、iPhoneと通話ゲートウェイのアドレスも設定します。

```ini
LINE_LEGACY_PHONE_IP=192.168.1.20
LINE_LEGACY_CALL_HOST=192.168.1.10
```

現行プロフィールから電話番号を復元できない場合は、補完値も設定できます。

```ini
LINE_LEGACY_PHONE=+81...
```

`LINE_LEGACY_PHONE`はE.164形式で入力します。`SELF_MID`は初回ログイン時に作られる`bridge_identity.json`から取得するため、通常は空欄のままで構いません。

### 5. LINEアカウントへQRログインする

```sh
sudo -u linelegacy env \
  LINE_LEGACY_DIR=/opt/line-legacy \
  LINEJS_BRIDGE_DIR=/opt/line-legacy/linejs-bridge \
  node /opt/line-legacy/linejs-bridge/setup-login.mjs
```

接続種別は、通常は`1. iPad版`を選びます。表示されたQRコードを現行LINEのQRコードリーダーで読み取り、画面の案内に従って承認してください。成功すると認証トークン、アカウント情報、既存のE2EE鍵が`/opt/line-legacy`以下へ保存されます。

`authtoken.txt`と`<device>-storage.json`は、必ず同じログインで生成された組み合わせのまま使ってください。別のものを混ぜると、他端末のLetter Sealingに影響することがあります。通常は`ALLOW_E2EE_REGISTER=1`を付けません。

### 6. 起動する

```sh
sudo systemctl enable --now line-legacy.target
sudo systemctl --no-pager --full status line-legacy.target
sudo systemctl --no-pager --full status line-legacy-legy.service line-legacy-linejs-bridge.service
```

動画送信も使う場合は追加で実行します。

```sh
sudo -u linelegacy touch /opt/line-legacy/linejs-bridge/video_enabled
sudo systemctl enable --now line-legacy-video.service
```

ファイアウォールを使っている場合は、iPhoneのあるLANからTCP 80、443、8081への接続を許可します。インターネット全体へは公開しないでください。

### 7. iPhoneにTweakを設定する

[Releases](https://github.com/shima0625/line-legacy/releases)の`LINEBridge-0.1.0-ios6-armv7.deb`を脱獄済みのiOS 5/6端末へインストールします。現在の添付パッケージはiOS 6ターゲットのため、iOS 5では修正後のソースからビルドしてください。iOS 5／armv7対応Theosが必要です。

「設定 → LINE Bridge」で次の3項目を設定します。

- `LINE Bridgeを使用`: オン
- `サーバー`: 母艦のLAN IP（例: `192.168.1.10`）
- `証明書SHA-256`: 手順3で表示したフィンガープリント

「接続テスト」が成功したら「設定を反映」を押し、LINEを起動します。接続先の書き換えはTweakが行うため、端末のWi-Fi DNSは通常の設定のままで構いません。

## うまく動かないとき

- **接続テストが失敗する**: 母艦のIP、TCP 8081のファイアウォール、`line-legacy-cdn.service`の状態を確認します。
- **LINEが接続エラーになる**: フィンガープリント、TCP 80/443、`line-legacy-legy.service`の状態を確認します。
- **認証エラーが出る**: `journalctl -u line-legacy-linejs-bridge.service -n 100 --no-pager`を確認し、必要なら手順5のQRログインをやり直します。
- **スタンプやお知らせだけ失敗する**: ApacheとTCP 80を確認します。`curl -H 'Host: dl.stickershop.line.naver.jp' http://127.0.0.1/bridge/config`で母艦内の転送を確認できます。
- **動画送信が拒否される**: `video_enabled`の有無と`line-legacy-video.service`を確認します。
- **音声が0:00、通話で相手の声が出ない**: `sudo /opt/line-legacy/tools/patch-linejs.sh`を再実行します。`npm install`で`node_modules`が更新された後はパッチの再適用が必要です。

```sh
sudo systemctl --failed
sudo journalctl -u line-legacy-legy.service -u line-legacy-linejs-bridge.service -n 100 --no-pager
```

Python／Node部分はWindowsやmacOSでも手動起動できますが、同梱のインストーラと自動起動設定はUbuntu/systemd向けです。

## 通話とEAS1コーデックヘルパー

LINE 3.7.1の音声通話は、LINE独自の音声コーデックEAS1を使います。仕様は公開されていないため、本リポジトリはコーデック処理そのものを持っていません。同梱しているのは`src/eas1_helper.mjs`、つまりUnixドメインソケット越しに外部のヘルパープロセスへ鍵処理・エンコード・デコードを依頼するクライアント側だけです。

ヘルパー側は`eas1-helper/`に収録しています。LINE for Androidの音声ライブラリ`libamp.so`を、Androidランタイムを起動せずに読み込み、同じソケットプロトコルで応答する常駐プロセスです。ビルド手順とプロトコル仕様は[eas1-helper/README.md](eas1-helper/README.md)を参照してください。

`libamp.so`自体はLINEの著作物のため本リポジトリには含めません。自分で入手したLINE for Android 4.0.3のAPKから`lib/armeabi-v7a/libamp.so`を取り出して使ってください。ソケットのパスは`LINE_LEGACY_EAS1_SOCKET`で指定します。

ヘルパーの自己テストが通った後、通話用の2サービスを有効化します。

```sh
sudo systemctl enable --now line-legacy-eas1.service line-legacy-call.service
sudo systemctl --no-pager --full status line-legacy-eas1.service line-legacy-call.service
```

通話を使う場合は、iPhoneのあるLANからUDP 19000と20000への接続も許可してください。

ヘルパーを用意しない場合、通話以外の機能はそのまま利用できます。

## プッシュ通知（Skyglow）

iOS 6の端末は現在ほとんどAPNsを受け取れないため、通知にはSkyglow（旧環境向けのサードパーティ製プッシュ通知基盤）を使います。

Skyglowはクライアント側デーモンのみが公開されており、サーバーは各自で用意する前提です。公開された共用サーバーは存在しません。

- 配布元: https://github.com/ObscureMosquito/Skyglow-Notifications
- サーバーは同梱のDockerfileからビルドし、互換ゲートウェイと同じホストで動かします。既定ではHTTPが3023番、TCPが21138番です。
- `src/line_skyglow_notify.py`は端末の配送先トークンを`docker exec skyglow-server-postgres-1 psql …`で読みます。`line-legacy-skyglow.service`を動かすユーザー（既定は`linelegacy`）が`docker`を実行できないと、通知は`permission denied … docker.sock`で全部失敗します。`usermod -aG docker linelegacy`のように権限を与えるか、Skyglowを同じユーザーで動かしてください。

### サーバーのホスト名に注意

サーバーのホスト名に`.local`を使わないでください。iOSは`.local`をmDNS専用として扱うため、通常のDNSへ問い合わせが飛ばず、端末登録に失敗します。`.test`など別のローカル用ドメインを使ってください。本リポジトリの既定値は`linepush.test`です。

`dns_probe.py`が`_sgn.linepush.test`のTXTレコードとして、`LINE_LEGACY_SERVER_IP`のアドレスとポート（`tcp_port=21138` / `http_addr=…:3023`）を返します。端末側でアドレスを直接設定する必要はありません。

### 端末側の設定

1. 端末にSkyglowを導入します。デーモン`/usr/libexec/SkyglowNotificationsDaemon`（launchd `com.skyglow.snd`）、SpringBoard側の`SGNSpringboard.dylib`、設定バンドル`SGNPreferenceBundle`が入ります。
2. 設定バンドルで、サーバーのアドレスとサーバー証明書のPEMを登録します。これらはplistではなくキーチェーンへ保存されます。
3. `~/Library/Preferences/com.skyglow.sndp.plist`の`appStatus`で`jp.naver.line`を有効にします。
4. 同じplistの`enabled`を有効にします。ここがオフのままだと、他の設定が正しくても通知は届きません。
5. 設定画面の状態が`Connected`になり、`jp.naver.line`が登録済みと表示されれば完了です。

ブリッジ側は`line_skyglow_notify.py`が担当します。受信メッセージ（`recv_out.jsonl`）と着信イベント（`call_ops.jsonl`）を追尾し、`LINE_LEGACY_SKYGLOW_URL`へ転送します。`line-legacy-skyglow.service`を有効化すると常駐します。

通知を使わない場合、このサービスを有効化しなければ他の機能に影響はありません。

## LINEBridge Tweak

Tweakの設定画面で、互換サーバーの接続先と証明書情報を指定します。

ビルド済みパッケージはReleasesに添付しています。自分でビルドする場合は、iOS 5／armv7対応のTheos環境で次を実行します。

```sh
cd tweak
make package
```

設定画面で互換サーバーのホストまたはIPアドレスと、その証明書のSHA-256フィンガープリントを入力します。公開ソースには実環境の値を設定していません。


## ライセンス

本リポジトリのコードはMIT Licenseです（`LICENSE`）。実行時に次の外部ソフトウェアを利用しますが、`node_modules`、ffmpeg本体、Node.js、Pythonは同梱していません。

| Component | Version | License | Source |
| --- | --- | --- | --- |
| @evex/linejs | 3.2.1 | MIT | https://github.com/evex-dev/linejs |
| opusscript | 0.1.1 | MIT | https://github.com/abalabahaha/opusscript |
| qrcode-terminal | 0.12.0 | Apache-2.0 | https://github.com/gtanner/qrcode-terminal |
| ffmpeg | 利用環境による | 構成による | https://ffmpeg.org/ |

`patches/linejs-3.2.1-call.patch`は、MIT Licenseで公開されている`@evex/linejs` 3.2.1の一部へ互換修正を適用します。

Copyright (c) 2024-2026 Evex Developers

LINEの名称および商標は、それぞれの権利者に帰属します。

## 注意

非公開APIと廃止済みプロトコルに依存するため、将来も動作する保証はありません。ゲートウェイをインターネットへ直接公開せず、信頼できるLAN内で利用してください。アカウント停止やデータ消失を含むリスクを理解した上で、自分が所有・管理する環境だけで使用してください。
