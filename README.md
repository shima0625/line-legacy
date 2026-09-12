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
- iOS 6用LINEBridge Tweak（接続先変更、証明書ピン留め、受信済み非所持スタンプの再起動後復元）

タイムラインは既定でフォロー中の投稿だけを表示します。VOOMのおすすめ投稿も不足分へ混ぜたい場合だけ、`TIMELINE_INCLUDE_RECOMMENDED=1`を設定してください。

## 対応しないもの・制限

- ファイル送信（クライアント側への搭載はLINE 5.3.0以降のため対象外）
- グループ通話（LINE 3.7.1自体に機能がありません）
- Tweakを使わずに、非所持の受信スタンプを再起動後も表示する処理
- **このゲートウェイ同士の通話**（両端が本ブリッジのとき、PLANETのメディア鍵が噛み合わず、双方の声がノイズになります。相手が通常のLINEクライアントであれば問題ありません）

非所持スタンプ復元機能は、LINE自身が保存した受信スタンプ用キャッシュを起動時に再読込します。パッケージを購入済み・使用可能として登録せず、所持スタンプ一覧にも追加しません。

## 構成

- `src/bridge_worker.mjs`: 現行アカウントとの送受信、連絡先・グループ同期
- `src/legy_proxy.py`: 3.7.1向けThrift/SPDY互換ゲートウェイ
- `src/cdn_proxy.py`: 画像・動画・スタンプ・タイムライン用CDN互換処理
- `src/local_worker.py`: 旧アプリとLINEJSワーカー間のローカルキュー
- `src/legacy_*.py`: グループ、スタンプ、ホーム、ノート等の互換処理
- `src/video_worker.mjs`: E2EE動画送信
- `src/legacy_call_gateway.mjs`: 通話ゲートウェイ
- `src/line_skyglow_notify.py`: Skyglowサーバーへのプッシュ通知転送
- `eas1-helper/`: 通話に使うEAS1コーデックヘルパー（要`libamp.so`）
- `tweak/`: iOS 6／armv7用LINEBridge Tweakソース
- `systemd/`: `/opt/line-legacy`向けサービス例
- `tools/`: インストール、簡易動作確認

## 必要なもの

- Linux、WindowsまたはmacOSホストと、Python 3、Node.js、ffmpeg／ffprobe（動画送信、動画サムネイルの生成、音声メッセージの長さ測定に使います。入っていないと動画のサムネイルが出ず、音声の長さが0:00になります）
- 旧アプリからの**HTTP 80番**を受けられること（スタンプ・着せ替え・お知らせは80番へ来ます。同梱の`apache/line-legacy-content.conf`を参照）
- Python依存パッケージ（`src/requirements.txt`。`akad`と`thrift`のみ）
- `@evex/linejs`等のNode依存パッケージ
- 自分で作成したTLS証明書
- Tweakを自分でビルドする場合はiOS 6／armv7対応Theos
- 通話を使う場合はEAS1コーデックヘルパー（同梱していません。下記参照）
- プッシュ通知を使う場合はSkyglowサーバーと、端末側のSkyglow（下記参照）

## セットアップ概要

1. `.env.example`を`/etc/line-legacy/line-legacy.env`へコピーし、自分の環境のアドレスを設定します。
2. `sudo tools/install-files.sh`でファイルとsystemdユニットを配置します。このスクリプトはサービスを起動しません。
3. `/opt/line-legacy`に仮想環境を作り、Python依存パッケージを入れます。systemdユニットは`/opt/line-legacy/venv/bin/python`を使います。

   ```sh
   python3 -m venv /opt/line-legacy/venv
   /opt/line-legacy/venv/bin/pip install -r /opt/line-legacy/requirements.txt
   ```

4. `/opt/line-legacy/linejs-bridge`で`npm install`を実行します。`@evex/linejs`はnpmではなくJSRで配布されているため、同梱の`.npmrc`が`@jsr`スコープのレジストリを指定しています。この`.npmrc`が無いと取得に失敗します。
5. `sudo /opt/line-legacy/tools/patch-linejs.sh`を実行します。素の`@evex/linejs` 3.2.1は通話のメディア鍵を解けず（相手の声が出ません）、音声メッセージに長さを付けません。同梱の`patches/linejs-3.2.1-call.patch`がその2点を直します。既に当たっている場合は何もしません。
6. `node setup-login.mjs`を実行し、表示されたQRコードを自分のLINEで読み取ります。このスクリプトは認証トークン、mid、X-Line-Applicationの3点を`bridge_identity.json`へまとめて書き出します。この3点が揃っていないと、現行サーバーへ中継する要求が認証エラーで弾かれます。またQRハンドシェイクで渡されるアカウントの既存E2EE鍵を引き継ぎます。鍵を新規登録すると、同じアカウントの他の端末のLetter Sealingを奪う（相手からの暗号化メッセージがスマホで読めなくなる）ため、既定では新規登録しません。
7. 自分の証明書とネットワーク経路を設定してから、必要なサービスだけを有効化します。`line-legacy.target`にはお知らせ更新タイマーも含まれます。動画送信を使う場合は`/opt/line-legacy/linejs-bridge/video_enabled`を作り、`line-legacy-video.service`を有効にしてください（このファイルが無いと動画送信は拒否されます）。

`setup-login.mjs`は認証トークン（`authtoken.txt`）と、E2EE鍵を含むストレージ（`<device>-storage.json`）をホスト上へ保存します。この2つは同じログインで生成された組み合わせのまま使ってください。別のものを混ぜると新しいE2EE鍵が登録され、同じアカウントを使う他の端末で暗号化メッセージが読めなくなることがあります。

## 対応OS

Python／Nodeで構成されるメッセージ、連絡先、グループ、CDN、ホーム／ノートの各サービスは、パスと待受アドレスを環境変数で設定すればWindows・macOSでも手動起動できます。

同梱の`tools/install-files.sh`と`systemd/`はLinux用の起動例です。Windowsではサービス登録、macOSではlaunchd設定を別途用意してください。また、53番・443番ポートの待受にはOSごとの管理者権限やファイアウォール設定が必要です。通話機能はEAS1ヘルパーとのローカルソケット接続を使うため、現在の配布設定はLinux向けです。他OSでは`LINE_LEGACY_EAS1_SOCKET`とヘルパー側の接続方式を合わせる必要があります。

## 通話とEAS1コーデックヘルパー

LINE 3.7.1の音声通話は、LINE独自の音声コーデックEAS1を使います。仕様は公開されていないため、本リポジトリはコーデック処理そのものを持っていません。同梱しているのは`src/eas1_helper.mjs`、つまりUnixドメインソケット越しに外部のヘルパープロセスへ鍵処理・エンコード・デコードを依頼するクライアント側だけです。

ヘルパー側は`eas1-helper/`に収録しています。LINE for Androidの音声ライブラリ`libamp.so`を、Androidランタイムを起動せずに読み込み、同じソケットプロトコルで応答する常駐プロセスです。ビルド手順とプロトコル仕様は[eas1-helper/README.md](eas1-helper/README.md)を参照してください。

`libamp.so`自体はLINEの著作物のため本リポジトリには含めません。自分で入手したLINE for Android 4.0.3のAPKから`lib/armeabi-v7a/libamp.so`を取り出して使ってください。ソケットのパスは`LINE_LEGACY_EAS1_SOCKET`で指定します。

また、依存パッケージのインストール後に`patches/linejs-conn-rsp-tranid.py`を実行し、利用中の`@evex/linejs`へ応答トランザクションID互換パッチを適用してください。

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

ビルド済みパッケージはReleasesに添付しています。自分でビルドする場合は、iOS 6／armv7対応のTheos環境で次を実行します。

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

`patches/linejs-conn-rsp-tranid.py`は、MIT Licenseで公開されている`@evex/linejs` 3.2.1の一部へ互換修正を適用します。

Copyright (c) 2024-2026 Evex Developers

LINEの名称および商標は、それぞれの権利者に帰属します。

## 注意

非公開APIと廃止済みプロトコルに依存するため、将来も動作する保証はありません。ゲートウェイをインターネットへ直接公開せず、信頼できるLAN内で利用してください。アカウント停止やデータ消失を含むリスクを理解した上で、自分が所有・管理する環境だけで使用してください。
