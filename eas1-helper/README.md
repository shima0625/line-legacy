# EAS1コーデックヘルパー

LINE 3.7.1の音声通話は、LINE独自の音声コーデックEAS1（`eas1/16000`）を使います。仕様は公開されておらず、互換実装も存在しません。3.7.1はSDPで`eas1/16000`と`telephone-event/8000`しか提示せず、内蔵のPCMU/PCMAを使わせる試みは成立しませんでした。

このディレクトリは、LINE for Androidに含まれる音声ライブラリ`libamp.so`を、Androidランタイムを起動せずに読み込み、Unixドメインソケット越しに符号化・復号を提供する常駐ヘルパーです。`src/legacy_call_gateway.mjs`が`src/eas1_helper.mjs`を通してこのソケットへ接続します。

**`libamp.so`はLINEの著作物です。本リポジトリには含まれておらず、再配布もしません。各自が自分で用意してください。**

## 収録物

| ファイル | 内容 |
| --- | --- |
| `amp_manual_loader.c` | ヘルパー本体。ELFの手動ロード、シンボル解決、ソケットサーバー |
| `amp_compat.c` | `libamp.so`が参照するBionic固有シンボルの補完（`_ctype_`、`__sF`、`__errno`、`__android_log_print`など） |
| `build.sh` | ビルドスクリプト |

## 必要なもの

- armv7（ハードフロート）向けクロスコンパイラ。例: `arm-linux-gnueabihf-gcc`
- armv7以外のホストで動かす場合はqemu-user（`qemu-arm`）
- 実行時に必要なarmhfの共有ライブラリ: `libm.so.6`、`libdl.so.2`、`libstdc++.so.6`、`libGLESv2.so.2`、`libgcc_s.so.1`

## 手順

### 1. libamp.soを用意する

自分で入手したLINE for Android 4.0.3のAPKを展開し、`lib/armeabi-v7a/libamp.so`をこのディレクトリへ置きます。

```sh
unzip -j line-4.0.3.apk lib/armeabi-v7a/libamp.so -d .
```

APKは署名を検証してから使ってください。他のバージョンでは、書き出し名や内部の呼び出し規約が異なる場合があります。

### 2. ビルドする

```sh
./build.sh
```

別の名前のツールチェーンを使う場合は`CC`を指定します。

```sh
CC=armv7l-linux-gnueabihf-gcc ./build.sh
```

### 3. 読み込みを確認する

引数を1つだけ渡すと、ソケットを開かずに読み込みと自己テストだけを実行します。armv7以外のホストでは`qemu-arm`を前に付けてください。

```sh
qemu-arm -L / ./eas1_helper ./libamp.so
```

成功すると次のように出ます。鍵変換と符号化・復号の往復がどちらも`PASS`なら、ヘルパーとして使える状態です。

```
relocations: relative=5127 glob=6 jump=183
manual load succeeded: base=0x40fde000 size=2469888
codec name: eas1
SRTP key transform: changed=1 saltUnchanged=1 restored=1
SRTP key roundtrip: PASS
eas1 create: encoder=0x42a890 error=0 decoder=0x431150 error=0
eas1 encode: bytes=63
eas1 decode: samples=320 energy=20857863125 first=0
eas1 roundtrip: PASS
```

アドレスと再配置の数は環境によって変わります。`unresolved symbol:` が出る場合は、そのシンボルを`amp_compat.c`へ追加してください。

### 4. 常駐させる

```sh
qemu-arm -L / ./eas1_helper --server /run/line-eas1/eas1.sock ./libamp.so
```

systemdで動かす場合は`systemd/line-legacy-eas1.service`を使います。このユニットは`/opt/line-legacy/eas1-helper/`の`eas1_helper`と`libamp.so`を実行します。`tools/install-files.sh`がソース一式をそこへ配置するので、その場でビルドするか、別の場所でビルドした`eas1_helper`と`libamp.so`を置いてください。ゲートウェイ側の接続先は`LINE_LEGACY_EAS1_SOCKET`で指定します。このヘルパーはネットワークを一切使わないため、`PrivateNetwork=yes`のまま動きます。

## ソケットプロトコル

別の実装を書く場合の仕様です。リクエスト・レスポンスとも12バイトのリトルエンディアンのヘッダに本体が続きます。本体は4096バイト以下です。

```
リクエスト: magic(u32) = 0x31415345 | operation(u32) | length(u32) | payload
レスポンス: magic(u32) = 0x31415345 | status(i32)    | length(u32) | payload
```

`status`が0以外ならエラーです。`operation`は次の5種類です。

| 値 | 操作 | 入力 | 出力 |
| --- | --- | --- | --- |
| 1 | 鍵の暗号化 | SDESの鍵 | 変換後の鍵 |
| 2 | 鍵の復号 | 変換後の鍵 | SDESの鍵 |
| 3 | コーデックの初期化 | なし | なし |
| 4 | 符号化 | PCM 16bit LE、16kHz | EAS1ペイロード |
| 5 | 復号 | EAS1ペイロード | PCM 16bit LE、16kHz |

鍵の変換（1と2）はコーデックとは別の処理です。3.7.1のAmpKitはSDESの鍵をそのままSDPへ載せず、独自に変換した形で交換します。生の鍵のまま扱うとSRTPの認証タグが一致しません。
