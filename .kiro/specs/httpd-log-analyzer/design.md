# 設計文書

## 概要

HTTPdログ解析ツールは、Apache/NginxのCommon Log Format（CLF）、Combined Log Format（access_log）、error_log、およびssl_request_logファイルを解析し、疑わしいアクセスパターンを検出するシェルスクリプトです。このツールは、高頻度アクセス、404エラーの多発、SQLインジェクション攻撃、認証失敗の頻発、WAFによってブロックされた攻撃、権限昇格の試行、存在しないファイルへのアクセス、ディレクトリトラバーサル攻撃などを検出し、IPアドレスの地理的位置情報と共に結果を出力します。

## アーキテクチャ

### システム構成

```
[ログファイル] → [ログタイプ判定] → [ログパーサー] → [パターン検出エンジン] → [地理位置検索] → [レポート生成]
                      ↓
              [access_log解析] / [error_log解析] / [ssl_request_log解析]
                      ↓
              [統合された脅威データ]
```

### 主要コンポーネント

1. **ログタイプ判定器**: access_log、error_log、ssl_request_logを自動識別
2. **ログパーサー**: ログエントリを解析し、構造化データに変換
3. **パターン検出エンジン**: 各種攻撃パターンを検出
4. **error_log解析器**: error_log特有の脅威パターンを検出
5. **ssl_request_log解析器**: SSL/TLSトラフィックの脅威パターンを検出
6. **ディレクトリトラバーサル検出器**: パストラバーサル攻撃を検出
7. **地理位置検索モジュール**: IPアドレスから国名を取得
8. **レポート生成器**: 結果を整形して出力

## コンポーネントとインターフェース

### 1. ログパーサー（parse_log_entry）

**入力**: ログエントリの1行
**出力**: 構造化されたログデータ（IP、タイムスタンプ、リクエスト、ステータスコード）

```bash
# Common Log Format: IP - - [timestamp] "request" status size
# Combined Log Format: IP - - [timestamp] "request" status size "referer" "user-agent"
```

**機能**:
- 正規表現を使用してログエントリを解析
- IPアドレス、タイムスタンプ、HTTPメソッド、URL、ステータスコード、サイズを抽出
- 不正な形式のログエントリをスキップ

### 2. 高頻度アクセス検出（detect_high_frequency）

**入力**: IPアドレス別のアクセス履歴
**出力**: 疑わしいIPアドレスのリスト

**アルゴリズム**:
- 5分間のスライディングウィンドウを使用
- 各IPアドレスについて、5分間で100回以上のアクセスを検出
- タイムスタンプをUnix時間に変換して効率的な計算を実行

### 3. 400系エラー検出（detect_4xx_errors）

**入力**: IPアドレス別の400系レスポンス履歴
**出力**: スキャン/攻撃活動の可能性があるIPアドレス

**アルゴリズム**:
- 5分間のスライディングウィンドウを使用
- 400-499の範囲のすべてのクライアントエラーをカウント
- 50回以上の400系エラーを持つIPを疑わしいとマーク
- 特定エラーコードの集中パターンを分析して攻撃タイプを推定
- 従来の404エラー検出（10回以上）と認証失敗検出（401/403で20回以上）も包括的に処理

**検出パターン**:
```bash
# 400系エラーコードと対応する攻撃タイプ
declare -A ERROR_ATTACK_TYPES=(
    ["400"]="不正リクエスト攻撃"
    ["401"]="認証失敗 - ブルートフォースの可能性"
    ["403"]="アクセス制御回避試行"
    ["404"]="リソース探索/偵察活動"
    ["405"]="HTTPメソッド攻撃"
    ["406"]="コンテンツネゴシエーション攻撃"
    ["408"]="タイムアウト攻撃"
    ["409"]="競合状態攻撃"
    ["410"]="削除済みリソース探索"
    ["413"]="ペイロード攻撃"
    ["414"]="URI長攻撃"
    ["415"]="メディアタイプ攻撃"
    ["429"]="レート制限回避試行"
)

# 特別な閾値設定
THRESHOLDS=(
    ["404"]=10      # 従来の404エラー検出
    ["401"]=20      # 認証失敗検出（10分間）
    ["403"]=20      # 認証失敗検出（10分間）
    ["default"]=50  # その他の400系エラー（5分間）
)
```

### 4. SQLインジェクション検出（detect_sql_injection）

**入力**: リクエストURL
**出力**: SQLインジェクション攻撃の可能性があるIPアドレス

**検出パターン**:
```bash
# 大文字小文字を区別しない検索パターン
PATTERNS=(
    "union.*select"
    "drop.*table"
    "insert.*into"
    "update.*set"
    "delete.*from"
    "script.*alert"
    "javascript:"
    "onload="
    "onerror="
    "%27.*union"  # URLエンコードされた'union
    "%22.*select" # URLエンコードされた"select
)
```

### 5. 地理位置検索（get_country_info）

**入力**: IPアドレス
**出力**: 国名

**実装方法**:
- 複数のAPIサービスを順次試行（ip-api.com、ipinfo.io、ipapi.co）
- `whois`コマンドを使用したフォールバック機能
- 5秒のタイムアウト設定でネットワーク遅延を防止
- キャッシュ機能により同一IPの重複検索を回避
- **包括的な国コードマッピング**: ISO 3166-1 alpha-2標準に基づく全世界195カ国の完全なマッピング

**国コード変換機能**:
- 2文字の国コード（例：JP、US、CN）を正式な国名に変換
- 国連加盟国195カ国すべてをサポート
- 主要な地域・領土（例：香港、台湾、プエルトリコ）も含む
- 不明な国コードの場合は元のコードを返す

```bash
# 例: 包括的な国コードマッピング実装
convert_country_code() {
    local country_code="$1"
    
    case "$country_code" in
        # 主要国
        "US") echo "United States" ;;
        "CN") echo "China" ;;
        "JP") echo "Japan" ;;
        "DE") echo "Germany" ;;
        "GB") echo "United Kingdom" ;;
        "FR") echo "France" ;;
        "RU") echo "Russia" ;;
        "KR") echo "South Korea" ;;
        "IN") echo "India" ;;
        "CA") echo "Canada" ;;
        "AU") echo "Australia" ;;
        "BR") echo "Brazil" ;;
        "IT") echo "Italy" ;;
        "ES") echo "Spain" ;;
        "NL") echo "Netherlands" ;;
        
        # アジア・太平洋地域
        "AF") echo "Afghanistan" ;;
        "BD") echo "Bangladesh" ;;
        "BT") echo "Bhutan" ;;
        "BN") echo "Brunei" ;;
        "KH") echo "Cambodia" ;;
        "FJ") echo "Fiji" ;;
        "ID") echo "Indonesia" ;;
        "IR") echo "Iran" ;;
        "IQ") echo "Iraq" ;;
        "IL") echo "Israel" ;;
        "JO") echo "Jordan" ;;
        "KZ") echo "Kazakhstan" ;;
        "KW") echo "Kuwait" ;;
        "KG") echo "Kyrgyzstan" ;;
        "LA") echo "Laos" ;;
        "LB") echo "Lebanon" ;;
        "MY") echo "Malaysia" ;;
        "MV") echo "Maldives" ;;
        "MN") echo "Mongolia" ;;
        "MM") echo "Myanmar" ;;
        "NP") echo "Nepal" ;;
        "KP") echo "North Korea" ;;
        "OM") echo "Oman" ;;
        "PK") echo "Pakistan" ;;
        "PW") echo "Palau" ;;
        "PG") echo "Papua New Guinea" ;;
        "PH") echo "Philippines" ;;
        "QA") echo "Qatar" ;;
        "SA") echo "Saudi Arabia" ;;
        "SG") echo "Singapore" ;;
        "LK") echo "Sri Lanka" ;;
        "SY") echo "Syria" ;;
        "TJ") echo "Tajikistan" ;;
        "TH") echo "Thailand" ;;
        "TL") echo "Timor-Leste" ;;
        "TR") echo "Turkey" ;;
        "TM") echo "Turkmenistan" ;;
        "AE") echo "United Arab Emirates" ;;
        "UZ") echo "Uzbekistan" ;;
        "VN") echo "Vietnam" ;;
        "YE") echo "Yemen" ;;
        
        # ヨーロッパ
        "AL") echo "Albania" ;;
        "AD") echo "Andorra" ;;
        "AM") echo "Armenia" ;;
        "AT") echo "Austria" ;;
        "AZ") echo "Azerbaijan" ;;
        "BY") echo "Belarus" ;;
        "BE") echo "Belgium" ;;
        "BA") echo "Bosnia and Herzegovina" ;;
        "BG") echo "Bulgaria" ;;
        "HR") echo "Croatia" ;;
        "CY") echo "Cyprus" ;;
        "CZ") echo "Czech Republic" ;;
        "DK") echo "Denmark" ;;
        "EE") echo "Estonia" ;;
        "FI") echo "Finland" ;;
        "GE") echo "Georgia" ;;
        "GR") echo "Greece" ;;
        "HU") echo "Hungary" ;;
        "IS") echo "Iceland" ;;
        "IE") echo "Ireland" ;;
        "LV") echo "Latvia" ;;
        "LI") echo "Liechtenstein" ;;
        "LT") echo "Lithuania" ;;
        "LU") echo "Luxembourg" ;;
        "MT") echo "Malta" ;;
        "MD") echo "Moldova" ;;
        "MC") echo "Monaco" ;;
        "ME") echo "Montenegro" ;;
        "MK") echo "North Macedonia" ;;
        "NO") echo "Norway" ;;
        "PL") echo "Poland" ;;
        "PT") echo "Portugal" ;;
        "RO") echo "Romania" ;;
        "SM") echo "San Marino" ;;
        "RS") echo "Serbia" ;;
        "SK") echo "Slovakia" ;;
        "SI") echo "Slovenia" ;;
        "SE") echo "Sweden" ;;
        "CH") echo "Switzerland" ;;
        "UA") echo "Ukraine" ;;
        "VA") echo "Vatican City" ;;
        
        # アフリカ
        "DZ") echo "Algeria" ;;
        "AO") echo "Angola" ;;
        "BJ") echo "Benin" ;;
        "BW") echo "Botswana" ;;
        "BF") echo "Burkina Faso" ;;
        "BI") echo "Burundi" ;;
        "CV") echo "Cape Verde" ;;
        "CM") echo "Cameroon" ;;
        "CF") echo "Central African Republic" ;;
        "TD") echo "Chad" ;;
        "KM") echo "Comoros" ;;
        "CG") echo "Congo" ;;
        "CD") echo "Democratic Republic of the Congo" ;;
        "DJ") echo "Djibouti" ;;
        "EG") echo "Egypt" ;;
        "GQ") echo "Equatorial Guinea" ;;
        "ER") echo "Eritrea" ;;
        "SZ") echo "Eswatini" ;;
        "ET") echo "Ethiopia" ;;
        "GA") echo "Gabon" ;;
        "GM") echo "Gambia" ;;
        "GH") echo "Ghana" ;;
        "GN") echo "Guinea" ;;
        "GW") echo "Guinea-Bissau" ;;
        "CI") echo "Ivory Coast" ;;
        "KE") echo "Kenya" ;;
        "LS") echo "Lesotho" ;;
        "LR") echo "Liberia" ;;
        "LY") echo "Libya" ;;
        "MG") echo "Madagascar" ;;
        "MW") echo "Malawi" ;;
        "ML") echo "Mali" ;;
        "MR") echo "Mauritania" ;;
        "MU") echo "Mauritius" ;;
        "MA") echo "Morocco" ;;
        "MZ") echo "Mozambique" ;;
        "NA") echo "Namibia" ;;
        "NE") echo "Niger" ;;
        "NG") echo "Nigeria" ;;
        "RW") echo "Rwanda" ;;
        "ST") echo "Sao Tome and Principe" ;;
        "SN") echo "Senegal" ;;
        "SC") echo "Seychelles" ;;
        "SL") echo "Sierra Leone" ;;
        "SO") echo "Somalia" ;;
        "ZA") echo "South Africa" ;;
        "SS") echo "South Sudan" ;;
        "SD") echo "Sudan" ;;
        "TZ") echo "Tanzania" ;;
        "TG") echo "Togo" ;;
        "TN") echo "Tunisia" ;;
        "UG") echo "Uganda" ;;
        "ZM") echo "Zambia" ;;
        "ZW") echo "Zimbabwe" ;;
        
        # 南北アメリカ
        "AG") echo "Antigua and Barbuda" ;;
        "AR") echo "Argentina" ;;
        "BS") echo "Bahamas" ;;
        "BB") echo "Barbados" ;;
        "BZ") echo "Belize" ;;
        "BO") echo "Bolivia" ;;
        "CL") echo "Chile" ;;
        "CO") echo "Colombia" ;;
        "CR") echo "Costa Rica" ;;
        "CU") echo "Cuba" ;;
        "DM") echo "Dominica" ;;
        "DO") echo "Dominican Republic" ;;
        "EC") echo "Ecuador" ;;
        "SV") echo "El Salvador" ;;
        "GD") echo "Grenada" ;;
        "GT") echo "Guatemala" ;;
        "GY") echo "Guyana" ;;
        "HT") echo "Haiti" ;;
        "HN") echo "Honduras" ;;
        "JM") echo "Jamaica" ;;
        "MX") echo "Mexico" ;;
        "NI") echo "Nicaragua" ;;
        "PA") echo "Panama" ;;
        "PY") echo "Paraguay" ;;
        "PE") echo "Peru" ;;
        "KN") echo "Saint Kitts and Nevis" ;;
        "LC") echo "Saint Lucia" ;;
        "VC") echo "Saint Vincent and the Grenadines" ;;
        "SR") echo "Suriname" ;;
        "TT") echo "Trinidad and Tobago" ;;
        "UY") echo "Uruguay" ;;
        "VE") echo "Venezuela" ;;
        
        # オセアニア
        "FM") echo "Micronesia" ;;
        "KI") echo "Kiribati" ;;
        "MH") echo "Marshall Islands" ;;
        "NR") echo "Nauru" ;;
        "NZ") echo "New Zealand" ;;
        "WS") echo "Samoa" ;;
        "SB") echo "Solomon Islands" ;;
        "TO") echo "Tonga" ;;
        "TV") echo "Tuvalu" ;;
        "VU") echo "Vanuatu" ;;
        
        # 特別地域・領土
        "HK") echo "Hong Kong" ;;
        "TW") echo "Taiwan" ;;
        "MO") echo "Macau" ;;
        "PR") echo "Puerto Rico" ;;
        "VI") echo "U.S. Virgin Islands" ;;
        "GU") echo "Guam" ;;
        "AS") echo "American Samoa" ;;
        
        # 不明な国コードの場合は元のコードを返す
        *) echo "$country_code" ;;
    esac
}

# 例: 複数サービスでのフォールバック実装
get_country_info() {
    local ip=$1
    local country=""
    
    # Try ip-api.com first
    country=$(timeout 5 curl -s "http://ip-api.com/line/$ip?fields=country" 2>/dev/null)
    if [ -n "$country" ] && [ "$country" != "fail" ]; then
        echo "$country"
        return
    fi
    
    # Fallback to ipinfo.io (returns 2-letter country code)
    country=$(timeout 5 curl -s "https://ipinfo.io/$ip/country" 2>/dev/null)
    if [ -n "$country" ] && [ ${#country} -eq 2 ]; then
        # Convert country code to full name using comprehensive mapping
        country=$(convert_country_code "$country")
        echo "$country"
        return
    fi
    
    # Final fallback
    echo "不明"
}
```

### 6. 使用方法表示（show_usage）

**入力**: なし
**出力**: 使用方法のヘルプメッセージ

**機能**:
- スクリプトの基本的な使用法を表示
- 具体的な実行例を提供
- 各オプションの説明を含む

### 7. ログファイル形式検証（validate_log_format）

**入力**: ログファイルパス
**出力**: 検証結果（成功/失敗）

**機能**:
- ログファイルの最初の100行をサンプリング
- Common Log FormatまたはCombined Log Formatの妥当性を検証
- 有効なエントリの割合を計算し、50%未満の場合はエラー

### 8. URLデコード機能（url_decode）

**入力**: URLエンコードされた文字列
**出力**: デコードされた文字列

**機能**:
- %XX形式のURLエンコードを適切な文字に変換
- 不正なエンコードに対する例外処理
- SQLインジェクション検出の前処理として使用

### 9. ログタイプ判定（detect_log_type）

**入力**: ログファイルパス
**出力**: ログタイプ（access_log/error_log/ssl_request_log）

**機能**:
- ログファイルの最初の数行をサンプリング
- access_log、error_log、ssl_request_logの形式パターンを識別
- 混在ログファイルの場合は行ごとに判定

### 10. error_log解析（parse_error_log_entry）

**入力**: error_logエントリの1行
**出力**: 構造化されたエラーデータ（タイムスタンプ、レベル、IPアドレス、メッセージ）

**サポートする形式**:
```bash
# Apache error_log format
[timestamp] [level] [pid] [client IP:port] message

# Nginx error_log format  
timestamp level: message, client: IP, server: hostname, request: "request"
```

### 11. error_log攻撃パターン検出（detect_error_log_threats）

**入力**: 構造化されたエラーデータ
**出力**: 疑わしいIPアドレスと攻撃タイプ

**検出パターン**:
```bash
ERROR_PATTERNS=(
    "ModSecurity.*denied"           # WAF blocked attack
    "File does not exist"          # File enumeration
    "Permission denied"            # Privilege escalation attempt
    "script not found"             # Script injection attempt
    "Invalid URI in request"       # Malformed request
    "request failed: error reading the headers"  # HTTP flood
    "SSL handshake failed"         # SSL/TLS attack
    "AH01630.*client denied"       # Access control violation
)
```

### 12. ssl_request_log解析（parse_ssl_request_log_entry）

**入力**: ssl_request_logエントリの1行
**出力**: 構造化されたSSLリクエストデータ（IP、タイムスタンプ、リクエスト、ステータスコード）

**サポートする形式**:
```bash
# Apache ssl_request_log format
[timestamp] IP TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 "GET /path HTTP/1.1" 200

# Nginx ssl_access_log format  
IP - - [timestamp] "GET /path HTTP/1.1" 200 size "referer" "user-agent" ssl_protocol ssl_cipher
```

**機能**:
- SSL/TLSプロトコル情報を含むログエントリを解析
- 暗号化スイート情報を抽出
- 通常のHTTPリクエスト情報（IP、URL、ステータス）を取得

### 13. ディレクトリトラバーサル検出（detect_directory_traversal）

**入力**: リクエストURL
**出力**: ディレクトリトラバーサル攻撃の可能性があるIPアドレス

**検出パターン**:
```bash
# ディレクトリトラバーサルパターン
TRAVERSAL_PATTERNS=(
    "\.\./.*"                    # ../
    "\.\.\\.*"                   # ..\
    "%2e%2e%2f"                  # URLエンコードされた../
    "%2e%2e%5c"                  # URLエンコードされた..\
    "\.\.\.\.//.*"               # ....//
    "\.\.\.\.\\\\.*"             # ....\\
    "%252e%252e%252f"            # 二重URLエンコードされた../
    "\.\.%2f"                    # ..%2f
    "%2e%2e/"                    # %2e%2e/
    "\.\.%5c"                    # ..%5c
    "%c0%ae%c0%ae%c0%af"         # UTF-8エンコードされた../
    "%c1%9c"                     # 不正なUTF-8エンコード
)
```

**機能**:
- URLエンコードされたトラバーサルパターンをデコードして検出
- 二重エンコードや不正なエンコードも検出
- 同一IPからの複数回試行を追跡
- 5回以上の試行で高リスクとして分類

```bash
show_usage() {
    echo "使用方法: $0 <ログファイルパス>"
    echo ""
    echo "説明:"
    echo "  Apache/NginxのHTTPサーバーログを解析し、疑わしいアクセスパターンを検出します。"
    echo ""
    echo "例:"
    echo "  $0 /var/log/apache2/access.log"
    echo "  $0 /var/log/nginx/access.log"
    echo "  $0 ./test_access.log"
    echo ""
    echo "検出される攻撃パターン:"
    echo "  - 高頻度アクセス（5分間で100回以上）"
    echo "  - 複数の404エラー（10回以上）"
    echo "  - SQLインジェクション攻撃の試行"
    echo "  - 認証失敗の頻発（10分間で20回以上）"
}
```

## データモデル

### ログエントリ構造

```bash
# 連想配列として表現
declare -A log_entry=(
    ["ip"]="192.168.1.1"
    ["timestamp"]="[01/Jan/2024:12:00:00 +0000]"
    ["method"]="GET"
    ["url"]="/index.html"
    ["status"]="200"
    ["size"]="1234"
    ["user_agent"]="Mozilla/5.0..."
)
```

### 疑わしいアクセス記録

```bash
# 疑わしいIPの情報を格納
declare -A suspicious_ips=(
    ["192.168.1.100"]="高頻度アクセス:150回"
    ["10.0.0.50"]="SQLインジェクション攻撃の可能性"
    ["172.16.0.25"]="複数の404エラー:25回"
)
```

## エラーハンドリング

### 1. ファイル関連エラー

- ログファイルが存在しない場合: エラーメッセージを表示して終了
- ログファイルが読み取り不可の場合: 権限エラーメッセージを表示
- 空のログファイル: 「解析するデータがありません」メッセージを表示

### 2. ネットワーク関連エラー

- 地理位置検索APIが利用不可: 「不明」として処理を継続
- タイムアウト: 5秒のタイムアウトを設定し、失敗時は次のサービスを試行

### 3. データ解析エラー

- 不正なログ形式: 該当行をスキップし、警告メッセージを出力
- 日時解析エラー: 該当エントリをスキップし、処理を継続

### 4. 引数エラー

- 引数が提供されない場合: 使用方法を表示し、正常終了（終了コード0）
- 無効なファイルパス: エラーメッセージを表示し、異常終了（終了コード1）

## テスト戦略

### 1. 単体テスト

各関数の個別テスト:
- `parse_log_entry`: 様々なログ形式での解析テスト
- `detect_high_frequency`: 異なる時間間隔でのアクセスパターンテスト
- `detect_sql_injection`: 既知のSQLインジェクションパターンテスト
- `get_country_info`: 有効/無効IPアドレスでのテスト

### 2. 統合テスト

- サンプルログファイルを使用した全体的な動作テスト
- 複数の攻撃パターンが混在するログでのテスト
- 大容量ログファイルでのパフォーマンステスト

### 3. テストデータ

```bash
# テスト用ログエントリの例
test_logs=(
    '192.168.1.100 - - [01/Jan/2024:12:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
    '10.0.0.50 - - [01/Jan/2024:12:00:02 +0000] "GET /admin.php?id=1 UNION SELECT * FROM users HTTP/1.1" 200 567'
    '172.16.0.25 - - [01/Jan/2024:12:00:03 +0000] "GET /nonexistent.html HTTP/1.1" 404 0'
    '203.0.113.10 - - [01/Jan/2024:12:00:04 +0000] "POST /login HTTP/1.1" 401 0'
    '198.51.100.20 - - [01/Jan/2024:12:00:05 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0'
    '[01/Jan/2024:12:00:06 +0000] 203.0.113.30 TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 "GET /admin/../../../etc/shadow HTTP/1.1" 403'
)
```

### 4. パフォーマンス要件

- 1GBのログファイルを5分以内で処理
- メモリ使用量を500MB以下に制限
- 同時に最大1000個のユニークIPアドレスを処理
- ssl_request_logの追加処理による性能劣化を10%以下に抑制

## パフォーマンス最適化

### 1. チャンク処理機能（process_log_chunks）

**入力**: ログファイルパス、チャンクサイズ
**出力**: 統合された解析結果

**機能**:
- 大容量ログファイルを指定されたサイズのチャンクに分割
- 各チャンクを順次処理してメモリ使用量を制限
- 処理済みデータの適切な解放でメモリリークを防止
- 進捗表示機能で処理状況を可視化

```bash
process_log_chunks() {
    local log_file="$1"
    local chunk_size="${2:-1000}"  # デフォルト1000行
    local total_lines=$(wc -l < "$log_file")
    local current_line=0
    local chunk_num=1
    
    echo "処理開始: 総行数 $total_lines 行を $chunk_size 行ずつ処理します"
    
    while IFS= read -r line || [ -n "$line" ]; do
        # チャンク処理ロジック
        process_single_line "$line"
        
        ((current_line++))
        
        # 進捗表示
        if (( current_line % chunk_size == 0 )); then
            local progress=$((current_line * 100 / total_lines))
            echo "進捗: チャンク $chunk_num 完了 ($progress%)"
            
            # メモリクリーンアップ
            cleanup_chunk_data
            ((chunk_num++))
        fi
    done < "$log_file"
}
```

### 2. 地理位置検索オプション

**コマンドライン引数**: `--enable-geo`
**機能**: デフォルトで無効な地理位置検索を有効化

```bash
# グローバル変数で制御（デフォルトは無効）
ENABLE_GEO_LOOKUP=false

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --enable-geo)
                ENABLE_GEO_LOOKUP=true
                shift
                ;;
            --fast-mode)
                FAST_MODE=true
                shift
                ;;
            *)
                LOG_FILE="$1"
                shift
                ;;
        esac
    done
}

get_country_info_optimized() {
    local ip="$1"
    
    if [ "$ENABLE_GEO_LOOKUP" = false ]; then
        echo "N/A"
        return
    fi
    
    # 地理位置検索処理
    get_country_info "$ip"
}
```

### 3. 詳細モード機能

**コマンドライン引数**: `--detailed-mode`
**機能**: デフォルトの高速処理から詳細な包括的検出に切り替え

```bash
# デフォルトは高速モード
DETAILED_MODE=false

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --enable-geo)
                ENABLE_GEO_LOOKUP=true
                shift
                ;;
            --detailed-mode)
                DETAILED_MODE=true
                shift
                ;;
            *)
                LOG_FILE="$1"
                shift
                ;;
        esac
    done
}

detect_sql_injection_optimized() {
    local url="$1"
    local ip="$2"
    
    if [ "$DETAILED_MODE" = false ]; then
        # 高速モード: 基本的なパターンのみチェック
        if [[ "$url" =~ (union|select|drop|insert) ]]; then
            record_suspicious_ip "$ip" "SQLインジェクション攻撃の可能性"
        fi
    else
        # 詳細モード: 包括的な検出とURLデコード処理
        detect_sql_injection_detailed "$url" "$ip"
    fi
}
```

### 4. メモリ最適化

**機能**:
- 連想配列のサイズ制限
- 処理済みデータの定期的なクリーンアップ
- 大容量ファイル処理時のバッファ管理

```bash
# メモリ使用量制限
MAX_SUSPICIOUS_IPS=10000
MAX_CACHE_SIZE=5000

cleanup_chunk_data() {
    # 古いキャッシュデータを削除
    if [ ${#ip_cache[@]} -gt $MAX_CACHE_SIZE ]; then
        unset ip_cache
        declare -A ip_cache
    fi
    
    # 疑わしいIPリストのサイズ制限
    if [ ${#suspicious_ips[@]} -gt $MAX_SUSPICIOUS_IPS ]; then
        echo "警告: 疑わしいIPが上限に達しました。古いエントリを削除します。"
        # 最新のエントリのみ保持
        # 実装詳細は省略
    fi
}
```

### 5. 処理進捗表示

**機能**: リアルタイムでの処理状況表示

```bash
show_progress() {
    local current="$1"
    local total="$2"
    local progress=$((current * 100 / total))
    local bar_length=50
    local filled_length=$((progress * bar_length / 100))
    
    printf "\r進捗: ["
    printf "%*s" $filled_length | tr ' ' '='
    printf "%*s" $((bar_length - filled_length)) | tr ' ' '-'
    printf "] %d%% (%d/%d)" $progress $current $total
}
```

## セキュリティ考慮事項

1. **入力検証**: ログファイルパスの検証、ディレクトリトラバーサル攻撃の防止
2. **権限管理**: スクリプトは必要最小限の権限で実行
3. **一時ファイル**: 機密情報を含む一時ファイルの安全な削除
4. **ネットワーク通信**: HTTPS使用の推奨、API キーの安全な管理
5. **メモリ制限**: 大容量ファイル処理時のメモリ使用量制限
6. **処理時間制限**: 無限ループや長時間処理の防止