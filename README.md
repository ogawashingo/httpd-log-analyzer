# HTTPd Log Analyzer

高性能なApache/Nginx ログ解析ツール - C言語実装版

## 概要

HTTPd Log Analyzerは、Apache/NginxのWebサーバーログを解析し、疑わしいアクセスパターンや攻撃を検出する高性能なセキュリティ分析ツールです。C言語で実装されており、従来のシェルスクリプト版と比較して5-15倍の性能向上を実現しています。

## 主な機能

### 🚀 高性能処理
- **5-15倍の速度向上**: シェルスクリプト版と比較
- **マルチスレッド処理**: 4つのワーカースレッドによる並列処理
- **メモリ効率**: チャンク処理（1000行単位）による最適化
- **大容量ファイル対応**: ストリーミング処理でメモリ使用量を制限

### 📊 複数ログ形式対応
- **標準access_log**: `IP - - [timestamp] "request" status size`
- **タイムスタンプファースト**: `[timestamp] IP - - "request" status size`
- **認証付きログ**: `IP - username [timestamp] "request" status size`
- **空ユーザー名**: `IP - "" [timestamp] "request" status size`
- **SSL request_log**: `[timestamp] IP TLSv1.2 ... "request" status`
- **JSON-RPC SSL**: `[timestamp] IP TLSv1.2 ... "{\"id\":1,\"method\":\"...\"}" status`
- **error_log**: `[timestamp] [level] [client IP] message`
- **空/不完全リクエスト**: 400/408エラーの適切な処理

### 🛡️ 包括的セキュリティ検出

#### SQLインジェクション攻撃
- **基本攻撃**: UNION SELECT, DROP TABLE, INSERT INTO
- **高度技術**: extractvalue(), updatexml(), exp(), floor(rand())
- **時間ベース**: WAITFOR DELAY, BENCHMARK(), SLEEP(), pg_sleep()
- **Boolean-based blind**: AND 1=1, OR 1=1パターン
- **Union-based**: UNION ALL SELECT, ORDER BY列挙
- **WAFバイパス**: /*!SELECT*/, uni%6fn, sel%65ct, CHAR(), CONCAT()
- **NoSQL攻撃**: $ne, $gt, $regex, $where, $or[], $and[]
- **LDAP攻撃**: *)(, )(& , |(パターン
- **XML攻撃**: <!entity, <![CDATAパターン

#### その他の攻撃パターン
- **高頻度アクセス**: 5分間で100回以上のリクエスト
- **404エラースキャン**: 10回以上の404エラー
- **認証攻撃**: 20回以上の401/403エラー
- **ディレクトリトラバーサル**: ../, ..\\, URLエンコード変種
- **CONNECT悪用**: プロキシトンネリング攻撃
- **JSON-RPC攻撃**: API悪用とメソッド列挙
- **空リクエスト攻撃**: 不正なHTTPリクエスト

### 🌍 地理的位置情報
- IPアドレスの国別情報取得
- プライベートIPアドレスの適切な処理
- レート制限対応の地理位置検索

## インストール

### 必要な依存関係
```bash
# Ubuntu/Debian
sudo apt-get install gcc libcurl4-openssl-dev

# CentOS/RHEL
sudo yum install gcc libcurl-devel

# macOS
brew install curl
```

### コンパイル
```bash
gcc -O3 -pthread -o httpd-log-analyzer httpd-log-analyzer.c -lcurl
```

## 使用方法

### 基本的な使用法
```bash
# 基本的なログ解析
./httpd-log-analyzer /var/log/apache2/access.log

# デバッグモードで実行
./httpd-log-analyzer --debug /var/log/nginx/access.log

# 詳細情報付きで実行
./httpd-log-analyzer --verbose /var/log/apache2/access.log

# 地理位置情報を有効にして実行
./httpd-log-analyzer --enable-geo /var/log/apache2/access.log
```

### オプション
- `--debug`: デバッグ出力を有効化
- `--verbose`: 詳細な処理情報を表示
- `--enable-geo`: 地理位置情報の取得を有効化
- `-h, --help`: ヘルプメッセージを表示

### 出力例
```
=== HTTPd Log Analyzer Results ===
Processing time: 0.15 seconds
Total lines processed: 10,234
Suspicious IPs detected: 8

Top Suspicious IPs:
1. 192.168.1.100 (SQLインジェクション攻撃の可能性) - 15 incidents [アメリカ]
2. 10.0.0.200 (高頻度アクセス) - 120 incidents [プライベートIP]
3. 203.0.113.25 (複数の404エラー - 偵察の可能性) - 25 incidents [日本]
4. 106.75.188.200 (JSON-RPC攻撃試行) - 5 incidents [中国]
5. 144.24.250.0 (不正なCONNECTメソッド使用) - 3 incidents [ロシア]
```

## 対応するログ形式の例

### 標準access_log
```
192.168.1.100 - - [01/Aug/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
```

### 認証付きログ
```
153.231.216.179 - admin [05/Aug/2025:13:25:05 +0900] "GET /admin HTTP/1.1" 401 482
```

### JSON-RPC SSL
```
[30/Jul/2025:07:47:51 +0900] 106.75.188.200 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 "{\"id\":1,\"method\":\"getData\"}" 200
```

### 空リクエスト
```
71.6.158.166 - - [06/Aug/2025:13:49:08 +0900] "" 400 303
```

## 検出される攻撃パターンの例

### SQLインジェクション
```bash
# 基本的なUNION攻撃
GET /search?q=1' UNION SELECT username,password FROM users--

# WAFバイパス
GET /api?data=uni%6fn sel%65ct * fr%6fm users

# NoSQL攻撃
GET /api?filter[$ne]=null
```

### ディレクトリトラバーサル
```bash
GET /files?path=../../../etc/passwd
GET /download?file=..%2f..%2f..%2fetc%2fpasswd
```

### JSON-RPC攻撃
```json
{"id":1,"method":"deleteUser","params":{"id":"../../../etc/passwd"}}
```

## 性能比較

| 項目 | シェルスクリプト版 | C言語版 | 改善率 |
|------|-------------------|---------|--------|
| 処理速度 | 100% | 500-1500% | 5-15倍 |
| メモリ使用量 | 100% | 30-50% | 50-70%削減 |
| CPU使用率 | 100% | 25-40% | 60-75%削減 |
| 大容量ファイル | 制限あり | 制限なし | 大幅改善 |

## テスト

### テストファイルの実行
```bash
# 包括的なテスト
./httpd-log-analyzer test_comprehensive_attack_patterns.log

# JSON-RPCテスト
./httpd-log-analyzer test_json_rpc_ssl.log

# 高度SQLインジェクションテスト
./httpd-log-analyzer test_advanced_sql_injection.log
```

### 性能テスト
```bash
# 大容量ファイルでの性能測定
time ./httpd-log-analyzer large_log_file.log
```

## 開発情報

### アーキテクチャ
- **言語**: C言語
- **並行処理**: POSIX threads (pthread)
- **HTTP通信**: libcurl
- **メモリ管理**: 効率的な動的メモリ割り当て
- **パターンマッチング**: 最適化された文字列検索

### データ構造
```c
typedef struct {
    char ip[MAX_IP_LENGTH];
    time_t timestamp;
    char method[16];
    char url[MAX_URL_LENGTH];
    int status;
    long size;
    char user_agent[256];
    char username[64];
} log_entry_t;
```

### 設定可能な定数
```c
#define MAX_LINE_LENGTH 8192
#define MAX_URL_LENGTH 2048
#define MAX_IP_LENGTH 16
#define CHUNK_SIZE 1000
#define NUM_THREADS 4
#define HIGH_FREQ_THRESHOLD 100
#define ERROR_4XX_THRESHOLD 50
#define AUTH_FAILURE_THRESHOLD 20
```

## トラブルシューティング

### よくある問題

#### コンパイルエラー
```bash
# libcurlが見つからない場合
sudo apt-get install libcurl4-openssl-dev

# pthreadエラーの場合
gcc -pthread -o httpd-log-analyzer httpd-log-analyzer.c -lcurl
```

#### 実行時エラー
```bash
# 権限エラー
chmod +r /var/log/apache2/access.log

# メモリ不足
# より小さなチャンクサイズでコンパイル
gcc -DCHUNK_SIZE=500 -O3 -pthread -o httpd-log-analyzer httpd-log-analyzer.c -lcurl
```

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。

## 貢献

バグ報告、機能要求、プルリクエストを歓迎します。

## 更新履歴

### v2.0.0 (2025年8月)
- C言語による完全な再実装
- 5-15倍の性能向上
- マルチスレッド処理の実装
- 複数ログ形式への対応拡張
- 高度なSQLインジェクション検出
- JSON-RPC攻撃検出の追加
- WAFバイパス技術の検出

### v1.0.0 (2025年7月)
- 初期シェルスクリプト版のリリース
- 基本的な攻撃パターン検出
- 地理位置情報の取得