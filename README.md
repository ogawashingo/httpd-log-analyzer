# HTTPd Log Analyzer (C Implementation)

高性能なApache/Nginxログ解析ツールのC実装版です。シェルスクリプト版と比較して**5-15倍の速度向上**を実現します。

## 特徴

- **高速処理**: シェルスクリプト版の5-15倍の処理速度
- **マルチスレッド処理**: 大容量ファイルの並列処理
- **メモリ効率**: チャンク処理による効率的なメモリ使用
- **包括的検出**: SQLインジェクション、ディレクトリトラバーサル、高頻度アクセス等の検出
- **地理位置情報**: オプションでIPアドレスの地理的位置を取得
- **複数ログ形式対応**: access_log、error_log、ssl_request_log

## 必要な依存関係

### Linux/Ubuntu
```bash
sudo apt-get update
sudo apt-get install gcc libcurl4-openssl-dev
```

### CentOS/RHEL
```bash
sudo yum install gcc libcurl-devel
```

### macOS
```bash
# Xcode Command Line Tools
xcode-select --install

# Homebrew (if needed)
brew install curl
```

### Windows (WSL推奨)
```bash
# WSL (Windows Subsystem for Linux) を使用
sudo apt-get update
sudo apt-get install gcc libcurl4-openssl-dev
```

## ビルド方法

### 方法1: Makefileを使用
```bash
# 依存関係チェック
make check-deps

# ビルド
make

# 最適化ビルド
make performance

# デバッグビルド
make debug
```

### 方法2: 直接コンパイル
```bash
gcc -O3 -Wall -Wextra -std=c99 -pthread -o httpd-log-analyzer httpd-log-analyzer.c -lcurl -lpthread
```

### 方法3: ビルドスクリプト使用 (Linux/macOS)
```bash
chmod +x build.sh
./build.sh
```

## 使用方法

### クイックスタート
```bash
# 自動コンパイルとテスト
chmod +x test_compile.sh
./test_compile.sh

# パフォーマンス比較
chmod +x performance_test.sh
./performance_test.sh
```

### 基本的な使用方法
```bash
# 高速モード（デフォルト）
./httpd-log-analyzer /var/log/apache2/access.log

# Nginxログ
./httpd-log-analyzer /var/log/nginx/access.log

# サンプルファイルでテスト
./httpd-log-analyzer sample_access.log
./httpd-log-analyzer sample_error.log
./httpd-log-analyzer sample_ssl_request.log
```

### オプション付き実行
```bash
# 詳細モード
./httpd-log-analyzer --detailed-mode /var/log/apache2/access.log

# 地理位置検索有効
./httpd-log-analyzer --enable-geo /var/log/apache2/access.log

# 詳細出力
./httpd-log-analyzer --verbose /var/log/apache2/access.log

# デバッグモード
./httpd-log-analyzer --debug /var/log/apache2/access.log

# 全オプション組み合わせ
./httpd-log-analyzer --detailed-mode --enable-geo --verbose --debug /var/log/apache2/access.log
```

### ヘルプ表示
```bash
./httpd-log-analyzer --help
```

## 検出される攻撃パターン

### 1. 高頻度アクセス
- **閾値**: 5分間で100回以上のリクエスト
- **検出対象**: DDoS攻撃、ボット活動

### 2. 4xx系エラーの多発
- **閾値**: 5分間で50回以上の4xxエラー
- **検出対象**: スキャン活動、ブルートフォース攻撃
- **特別閾値**:
  - 404エラー: 10回以上で偵察活動
  - 401/403エラー: 20回以上で認証攻撃

### 3. SQLインジェクション攻撃
- **検出パターン**: UNION SELECT、DROP TABLE、INSERT INTO等
- **URLデコード**: エンコードされた攻撃パターンも検出
- **詳細モード**: より包括的なパターンマッチング

### 4. ディレクトリトラバーサル攻撃
- **検出パターン**: ../、..\\、URLエンコード版
- **リスク評価**: 5回以上で高リスク分類
- **UTF-8エンコード**: 不正なエンコードも検出

### 5. Error Logからの脅威検出
- ModSecurityブロック
- ファイルアクセス試行
- 権限昇格試行
- スクリプト実行試行

## パフォーマンス比較

| ファイルサイズ | シェルスクリプト版 | C実装版 | 改善倍率 |
|---------------|------------------|---------|----------|
| 小ファイル (1MB) | 2-3秒 | 0.2-0.5秒 | 6-10倍 |
| 中ファイル (100MB) | 2-5分 | 15-45秒 | 8-12倍 |
| 大ファイル (1GB) | 5-15分 | 1-3分 | 5-8倍 |

## 出力例

```
HTTPd Log Analyzer (C Implementation) - High Performance Version
Processing: /var/log/apache2/access.log
Processing 50000 lines from /var/log/apache2/access.log
Mode: Fast, Geo lookup: Disabled
Processing complete!
Total lines: 50000, Processed: 49850
Processing time: 12 seconds

=== HTTPd Log Analysis Report ===
Generated at: Fri Aug  8 15:30:45 2025
Analysis mode: Fast
Geographic lookup: Disabled

Suspicious IP addresses found: 5

IP Address      Count    Reason                                           Country
----------      -----    ------                                           -------
192.168.1.100   150      高頻度アクセス (150回/5分)                        N/A
10.0.0.50       25       SQLインジェクション攻撃の可能性                   N/A
172.16.0.25     15       リソース探索/偵察活動                             N/A
203.0.113.10    12       認証失敗 - ブルートフォースの可能性               N/A
198.51.100.20   8        ディレクトリトラバーサル攻撃の可能性               N/A

Summary:
- Total suspicious IPs: 5
- SQL injection attempts: 1
- Directory traversal attempts: 1
- High frequency access: 1
- 4xx error patterns: 2
```

## テスト用サンプルファイル

テスト用のサンプルログファイルを作成：

```bash
cat > sample_access.log << 'EOF'
192.168.1.100 - - [08/Aug/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
10.0.0.50 - - [08/Aug/2025:10:00:02 +0000] "GET /admin.php?id=1 UNION SELECT * FROM users HTTP/1.1" 200 567
172.16.0.25 - - [08/Aug/2025:10:00:03 +0000] "GET /nonexistent.html HTTP/1.1" 404 0
203.0.113.10 - - [08/Aug/2025:10:00:04 +0000] "POST /login HTTP/1.1" 401 0
198.51.100.20 - - [08/Aug/2025:10:00:05 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0
EOF

# テスト実行
./httpd-log-analyzer sample_access.log
```

## インストール

### システム全体にインストール
```bash
sudo make install
```

### アンインストール
```bash
sudo make uninstall
```

## トラブルシューティング

### コンパイルエラー

**libcurl not found**
```bash
# Ubuntu/Debian
sudo apt-get install libcurl4-openssl-dev

# CentOS/RHEL
sudo yum install libcurl-devel
```

**gcc not found**
```bash
# Ubuntu/Debian
sudo apt-get install gcc

# CentOS/RHEL
sudo yum install gcc
```

### 実行時エラー

**Permission denied**
```bash
# ログファイルの読み取り権限を確認
ls -la /var/log/apache2/access.log

# 必要に応じて権限変更
sudo chmod +r /var/log/apache2/access.log
```

**Segmentation fault**
- デバッグビルドで詳細確認: `make debug`
- 大容量ファイルの場合はメモリ不足の可能性

## 開発・カスタマイズ

### ソースコード構造
- `httpd-log-analyzer.c`: メインソースファイル
- `Makefile`: ビルド設定
- `build.sh`: 自動ビルドスクリプト

### カスタマイズポイント
- 検出パターンの追加/変更
- 閾値の調整
- 新しい攻撃タイプの追加
- 出力形式の変更

### デバッグ
```bash
# デバッグビルド
make debug

# デバッグ実行
./httpd-log-analyzer --debug --verbose sample_access.log
```

## ライセンス

このソフトウェアはMITライセンスの下で提供されています。

## 貢献

バグ報告、機能要求、プルリクエストを歓迎します。

## 関連ファイル

- `httpd-log-analyzer.sh`: 元のシェルスクリプト版
- `PERFORMANCE_IMPROVEMENTS_*.md`: パフォーマンス改善レポート
- `OPTIMIZATION_SUMMARY.md`: 最適化サマリー

## 更新履歴

- v1.0.0: 初回リリース（C実装版）
  - シェルスクリプト版の全機能を移植
  - 5-15倍の速度向上を実現
  - マルチスレッド処理対応
  - メモリ効率の大幅改善