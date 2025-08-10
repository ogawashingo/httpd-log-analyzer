#!/bin/bash

# HTTPd ログ解析ツール
# Apache/Nginxログファイルから疑わしいアクセスパターンを解析します

# グローバル変数
declare -A suspicious_ips
declare -A ip_access_times

# 疑わしいIP検出を全て格納するグローバル配列（IP毎に複数エントリ可能）
declare -a all_suspicious_detections

# 地理位置検索制御フラグ（デフォルトは無効）
ENABLE_GEO_LOOKUP=false

# 詳細モード制御フラグ（デフォルトは高速モード）
DETAILED_MODE=false

# コマンドライン引数解析結果格納変数
LOG_FILE_RESULT=""

# 高頻度アクセス検出変数
declare -A ip_access_history  # 各IPのアクセスタイムスタンプを格納
declare -A ip_access_counts   # 各IPのアクセス回数を格納

# メモリ最適化設定
MAX_SUSPICIOUS_IPS=10000      # 疑わしいIPの最大数
MAX_CACHE_SIZE=5000           # 地理位置キャッシュの最大サイズ
MAX_ACCESS_HISTORY=150        # IPごとのアクセス履歴の最大保持数
MAX_AUTH_FAILURES=50          # IPごとの認証失敗履歴の最大保持数
MAX_TOTAL_IPS=50000           # 全体のIP追跡数の上限
CLEANUP_INTERVAL=5000         # クリーンアップを実行する処理行数間隔

# 追加のメモリ最適化設定
MAX_LOG_ENTRY_LENGTH=8192     # 処理する最大ログエントリ長（バッファオーバーフロー防止）
MAX_URL_LENGTH=2048           # 処理する最大URL長
MEMORY_CHECK_INTERVAL=10000   # メモリ使用量チェック間隔

# パフォーマンス測定変数
declare -A performance_metrics
performance_metrics["start_time"]=$(date +%s)
performance_metrics["processed_lines"]=0
performance_metrics["cleanup_count"]=0
performance_metrics["memory_warnings"]=0
performance_metrics["skipped_lines"]=0
performance_metrics["detection_count"]=0
performance_metrics["cache_hits"]=0
performance_metrics["cache_misses"]=0

# 最適化フラグ
VERBOSE_OUTPUT=false
DEBUG_MODE=false
PERFORMANCE_MODE=true

# SQLインジェクション検出パターン（大文字小文字を区別しない）
declare -a SQL_INJECTION_PATTERNS=(
    "union.*select"
    "drop.*table"
    "insert.*into"
    "update.*set"
    "delete.*from"
    "script.*alert"
    "javascript:"
    "onload="
    "onerror="
    "%27.*union"     # URLエンコードされた ' union
    "%22.*select"    # URLエンコードされた " select
    "%3c.*script"    # URLエンコードされた < script
    "%3e"            # URLエンコードされた >
    "exec.*xp_"      # SQL Server拡張プロシージャ
    "sp_.*password"  # SQL Serverストアドプロシージャ
    "information_schema"
    "mysql.*user"
    "pg_.*user"      # PostgreSQLシステムテーブル
    "waitfor.*delay" # SQL Server時間遅延
    "benchmark.*("   # MySQLベンチマーク関数
    "sleep.*("       # MySQLスリープ関数
)

# 例と攻撃パターンを含む詳細な使用方法情報を表示する関数
show_usage() {
    echo "使用方法: $0 [オプション] <ログファイルパス>"
    echo ""
    echo "説明:"
    echo "  Apache/NginxのHTTPサーバーログを解析し、疑わしいアクセスパターンを検出します。"
    echo ""
    echo "オプション:"
    echo "  --enable-geo      地理位置検索を有効にします（デフォルトは無効）"
    echo "  --detailed-mode   詳細な攻撃パターン検出を有効にします（デフォルトは高速モード）"
    echo "  --debug           デバッグ出力を有効にします（詳細な検出ログ）"
    echo "  --verbose         詳細な処理情報を表示します"
    echo "  -h, --help        このヘルプメッセージを表示します"
    echo ""
    echo "例:"
    echo "  $0 /var/log/apache2/access.log"
    echo "  $0 --enable-geo /var/log/nginx/access.log"
    echo "  $0 --detailed-mode ./test_access.log"
    echo "  $0 --enable-geo --detailed-mode /var/log/apache2/access.log"
    echo ""
    echo "検出される攻撃パターン:"
    echo "  - 高頻度アクセス（5分間で100回以上のリクエスト）"
    echo "  - 複数の404エラー（10回以上の存在しないページへのアクセス - 偵察の可能性）"
    echo "  - SQLインジェクション攻撃の試行（UNION SELECT、DROP TABLEなどのパターン）"
    echo "  - 認証失敗の頻発（10分間で20回以上の401/403エラー - ブルートフォースの可能性）"
    echo "  - ディレクトリトラバーサル攻撃（../、..\\、URLエンコード版など - 5回以上で高リスク）"
    echo ""
    echo "処理モード:"
    echo "  高速モード（デフォルト）:"
    echo "    - 基本的な攻撃パターンのみを検出"
    echo "    - URLデコード処理を簡略化"
    echo "    - 高速処理でリアルタイム監視に適している"
    echo "  詳細モード（--detailed-mode）:"
    echo "    - 包括的な攻撃パターンマッチング"
    echo "    - 完全なURLデコード処理（二重エンコード対応）"
    echo "    - より精密な検出だが処理時間が長い"
    echo ""
    echo "サポートされるログ形式:"
    echo "  - Common Log Format (CLF)"
    echo "  - Combined Log Format"
    echo "  - Apache/Nginx error_log"
    echo "  - Apache ssl_request_log"
    echo ""
    echo "出力情報:"
    echo "  - 疑わしいIPアドレス"
    echo "  - 発生回数"
    echo "  - 検出理由"
    echo "  - 地理的位置情報（--enable-geoオプション使用時のみ、デフォルトは「N/A」）"
    echo ""
}

# 一貫したフォーマットでエラーメッセージを表示する関数
display_error() {
    local error_type="$1"
    local error_message="$2"
    local exit_code="${3:-1}"
    
    echo "ERROR [$error_type]: $error_message" >&2
    
    # エラータイプに基づいて有用な提案を提供
    case "$error_type" in
        "FILE_NOT_FOUND")
            echo "Suggestion: Check if the file path is correct and the file exists." >&2
            ;;
        "PERMISSION_DENIED")
            echo "Suggestion: Check file permissions or run with appropriate privileges." >&2
            echo "Try: chmod +r \"$error_message\" or run as a user with read access." >&2
            ;;
        "EMPTY_FILE")
            echo "Suggestion: Verify that the log file contains data or check if logging is enabled." >&2
            ;;
        "INVALID_ARGUMENT")
            echo "Suggestion: Run '$0' without arguments to see usage information." >&2
            ;;
        "INVALID_LOG_FORMAT")
            echo "Suggestion: Ensure the log file uses Common Log Format or Combined Log Format." >&2
            ;;
    esac
    
    if [ "$exit_code" -ne 0 ]; then
        exit "$exit_code"
    fi
}

# コマンドライン引数を検証する関数
validate_arguments() {
    # 引数の数をチェック - 引数が提供されない場合は使用方法を表示
    if [ $# -eq 0 ]; then
        show_usage
    elif [ $# -gt 1 ]; then
        display_error "INVALID_ARGUMENT" "Too many arguments provided. Expected 1, got $#" 1
    fi
    
    local log_file="$1"
    
    # ログファイルパス形式を検証
    if [ -z "$log_file" ]; then
        display_error "INVALID_ARGUMENT" "Log file path cannot be empty" 1
    fi
    
    # 潜在的なディレクトリトラバーサル攻撃をチェック
    if [[ "$log_file" =~ \.\./|\.\.\\ ]]; then
        display_error "INVALID_ARGUMENT" "Directory traversal patterns detected in file path" 1
    fi
    
    # ファイルが存在するかチェック
    if [ ! -e "$log_file" ]; then
        display_error "FILE_NOT_FOUND" "Log file '$log_file' does not exist" 1
    fi
    
    # 実際にファイルかどうかチェック（ディレクトリや特殊ファイルではない）
    if [ ! -f "$log_file" ]; then
        if [ -d "$log_file" ]; then
            display_error "INVALID_ARGUMENT" "'$log_file' is a directory, not a file" 1
        else
            display_error "INVALID_ARGUMENT" "'$log_file' is not a regular file" 1
        fi
    fi
    
    # 読み取り権限をチェック
    if [ ! -r "$log_file" ]; then
        display_error "PERMISSION_DENIED" "Cannot read log file '$log_file'" 1
    fi
    
    # ファイルが空かどうかチェック
    if [ ! -s "$log_file" ]; then
        display_error "EMPTY_FILE" "Log file '$log_file' is empty" 0
    fi
    
    # ファイルサイズを検証（極端に大きい場合は警告）とパフォーマンス推奨事項
    local file_size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo "0")
    local max_size=$((1024 * 1024 * 1024))  # 1GB制限
    local large_size=$((100 * 1024 * 1024))  # 100MB threshold
    
    if [ "$file_size" -gt "$max_size" ]; then
        echo "WARNING: Log file is very large ($(($file_size / 1024 / 1024)) MB)." >&2
        echo "Analysis may take considerable time and memory. Consider:" >&2
        echo "  - Splitting the file: split -l 100000 $log_file chunk_" >&2
        echo "  - Analyzing recent data only: tail -n 50000 $log_file > recent.log" >&2
        echo "  - Using head for sample analysis: head -n 10000 $log_file > sample.log" >&2
        echo ""
    elif [ "$file_size" -gt "$large_size" ]; then
        echo "INFO: Processing large file ($(($file_size / 1024 / 1024)) MB). This may take several minutes." >&2
        echo ""
    fi
    
    # 基本的なログ形式検証 - 最初の数行をチェック
    validate_log_format "$log_file"
}

# ログファイル形式を検証する関数
# ファイルが有効なApache/Nginxログエントリ（access_logまたはerror_log）を含むかチェック
validate_log_format() {
    local log_file="$1"
    local valid_entries=0
    local total_checked=0
    local max_check=10  # 最初の10行の空でない行をチェック
    
    if [ "$VERBOSE_OUTPUT" = true ]; then
        echo "Validating log file format..." >&2
    fi
    
    while IFS= read -r line && [ $total_checked -lt $max_check ]; do
        # 空行とコメントをスキップ
        if [ -z "$line" ] || [[ "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        ((total_checked++))
        
        # access_log形式をチェック（Common Log FormatまたはCombined Log Format）
        # パターン: IP - - [timestamp] "request" status size [optional fields]
        if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*-.*-.*\[.*\].*\".*\".*[0-9]+.*[0-9-]+ ]]; then
            ((valid_entries++))
        # Apache error_log形式をチェック
        # パターン: [timestamp] [level] [pid] [client IP:port] message
        elif [[ "$line" =~ ^\[.*\][[:space:]]+\[.*\][[:space:]]+\[.*\][[:space:]]+\[client[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+\] ]]; then
            ((valid_entries++))
        # Nginx error_log形式をチェック
        # パターン: timestamp level: message, client: IP, server: hostname
        elif [[ "$line" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]+\[.*\].*client:[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*server: ]]; then
            ((valid_entries++))
        # 簡略化されたerror_log形式をチェック
        # パターン: [timestamp] [level] client IP message
        elif [[ "$line" =~ ^\[.*\][[:space:]]+\[.*\][[:space:]]+client[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            ((valid_entries++))
        # 汎用error_logパターンをチェック（フォールバック）
        elif [[ "$line" =~ ^\[.*\].*\[.*\].*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            ((valid_entries++))
        # Apache ssl_request_log形式をチェック
        # パターン: [timestamp] IP TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 "GET /path HTTP/1.1" 200
        elif [[ "$line" =~ ^\[.*\][[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+TLS.*[[:space:]]+.*[[:space:]]+\".*\"[[:space:]]+[0-9]+ ]]; then
            ((valid_entries++))
        # Nginx ssl_access_log形式をチェック
        # パターン: IP - - [timestamp] "GET /path HTTP/1.1" 200 size "referer" "user-agent" ssl_protocol ssl_cipher
        elif [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+-[[:space:]]+-[[:space:]]+\[.*\][[:space:]]+\".*\"[[:space:]]+[0-9]+[[:space:]]+[0-9-]+.*TLS ]]; then
            ((valid_entries++))
        else
            echo "WARNING: Potentially invalid log format detected in line $total_checked: ${line:0:100}..." >&2
        fi
    done < "$log_file"
    
    # 有効なエントリが見つかったかチェック
    if [ $valid_entries -eq 0 ] && [ $total_checked -gt 0 ]; then
        display_error "INVALID_LOG_FORMAT" "No valid log entries found in the first $total_checked lines. File may not be in Apache/Nginx access_log, error_log, or ssl_request_log format" 1
    elif [ $total_checked -eq 0 ]; then
        display_error "EMPTY_FILE" "No non-empty lines found in log file" 1
    fi
    
    # 有効性パーセンテージを計算
    local validity_percentage=0
    if [ $total_checked -gt 0 ]; then
        validity_percentage=$(( (valid_entries * 100) / total_checked ))
    fi
    
    if [ "$VERBOSE_OUTPUT" = true ]; then
        echo "Log format validation complete: $valid_entries/$total_checked lines appear valid (${validity_percentage}%)" >&2
    fi
    
    # 有効性が低い場合は警告
    if [ $validity_percentage -lt 50 ] && [ $total_checked -gt 2 ]; then
        echo "WARNING: Low validity percentage detected. Results may be unreliable." >&2
        echo "Please verify that the file is in Apache/Nginx access_log, error_log, or ssl_request_log format." >&2
    fi
    
    echo "" >&2
}

# ログエントリを解析してコンポーネントを抽出する関数
# Common Log FormatとCombined Log Formatの両方をサポート
# 最適化: パフォーマンス向上とメモリ使用量削減
parse_log_entry() {
    local log_line="$1"
    local line_number="${2:-unknown}"
    
    # 空行とコメント行をスキップ
    if [ -z "$log_line" ] || [[ "$log_line" =~ ^[[:space:]]*# ]]; then
        ((performance_metrics["skipped_lines"]++))
        return 1
    fi
    
    # バッファオーバーフロー防止：ログエントリの長さ制限
    if [ ${#log_line} -gt $MAX_LOG_ENTRY_LENGTH ]; then
        if (( line_number % 1000 == 1 )); then
            echo "Warning: Log entry too long at line $line_number (${#log_line} chars), truncating..." >&2
        fi
        log_line="${log_line:0:$MAX_LOG_ENTRY_LENGTH}"
        ((performance_metrics["skipped_lines"]++))
    fi
    
    # 前回の呼び出しからの汚染を避けるために変数を初期化
    LOG_IP=""
    LOG_TIMESTAMP=""
    LOG_REQUEST=""
    LOG_STATUS=""
    LOG_SIZE=""
    LOG_METHOD=""
    LOG_URL=""
    
    # パフォーマンス向上のためawkの代わりにbash組み込み機能を使用した最適化された解析
    # IP抽出（最初のフィールド） - 単純な抽出ではawkより高速
    LOG_IP="${log_line%% *}"
    
    # 基本的なIP検証
    if [[ ! $LOG_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # 出力オーバーヘッドを削減するため100エラーごとに警告を表示
        if (( line_number % 100 == 1 )); then
            echo "Warning: Invalid IP format at line $line_number: ${log_line:0:80}..." >&2
        fi
        return 1
    fi
    
    # タイムスタンプ抽出（[と]の間） - 最適化された正規表現
    if [[ $log_line =~ \[([^\]]+)\] ]]; then
        LOG_TIMESTAMP="${BASH_REMATCH[1]}"
    else
        if (( line_number % 100 == 1 )); then
            echo "Warning: Invalid timestamp at line $line_number: ${log_line:0:80}..." >&2
        fi
        return 1
    fi
    
    # リクエスト抽出（引用符の間） - パフォーマンス最適化
    if [[ $log_line =~ \"([^\"]+)\" ]]; then
        LOG_REQUEST="${BASH_REMATCH[1]}"
    else
        if (( line_number % 100 == 1 )); then
            echo "Warning: Invalid request at line $line_number: ${log_line:0:80}..." >&2
        fi
        return 1
    fi
    
    # 最適化されたアプローチを使用してステータスとサイズを抽出
    # 引用符で囲まれたリクエストの後の部分を見つける
    local after_request="${log_line#*\"$LOG_REQUEST\"}"
    after_request="${after_request# }"  # 先頭のスペースを削除
    
    # ステータス抽出（リクエスト後の最初のフィールド）
    LOG_STATUS="${after_request%% *}"
    
    # 基本的なステータス検証
    if [[ ! $LOG_STATUS =~ ^[0-9]{3}$ ]]; then
        if (( line_number % 100 == 1 )); then
            echo "Warning: Invalid status code at line $line_number: $LOG_STATUS" >&2
        fi
        return 1
    fi
    
    # サイズ抽出（リクエスト後の2番目のフィールド） - パフォーマンスのためオプション
    after_request="${after_request#$LOG_STATUS }"
    LOG_SIZE="${after_request%% *}"
    
    # リクエストからHTTPメソッドとURLを抽出 - 最適化
    if [[ $LOG_REQUEST =~ ^([A-Z]+)[[:space:]]+([^[:space:]]+) ]]; then
        LOG_METHOD="${BASH_REMATCH[1]}"
        LOG_URL="${BASH_REMATCH[2]}"
        
        # URL長の制限（セキュリティとパフォーマンス向上）
        if [ ${#LOG_URL} -gt $MAX_URL_LENGTH ]; then
            if (( line_number % 1000 == 1 )); then
                echo "Warning: URL too long at line $line_number (${#LOG_URL} chars), truncating..." >&2
            fi
            LOG_URL="${LOG_URL:0:$MAX_URL_LENGTH}"
        fi
    else
        # 不正な形式のリクエストを適切に処理
        LOG_METHOD="UNKNOWN"
        LOG_URL="$LOG_REQUEST"
        # パフォーマンスのため警告頻度を削減
        if (( line_number % 500 == 1 )); then
            echo "Warning: Could not parse HTTP method/URL at line $line_number" >&2
        fi
    fi
    
    return 0
}

# URLエンコードされた文字列をデコードする関数
url_decode() {
    local encoded_string="$1"
    
    # URLエンコーディングを実際の文字に変換
    # SQLインジェクション攻撃で使用される一般的なURLエンコーディングを処理
    local decoded_string="$encoded_string"
    
    # 一般的なURLエンコーディングを置換
    decoded_string="${decoded_string//%20/ }"      # スペース
    decoded_string="${decoded_string//%27/\'}"     # シングルクォート
    decoded_string="${decoded_string//%22/\"}"     # ダブルクォート
    decoded_string="${decoded_string//%3C/<}"      # 小なり
    decoded_string="${decoded_string//%3E/>}"      # 大なり
    decoded_string="${decoded_string//%28/(}"      # 左括弧
    decoded_string="${decoded_string//%29/)}"      # 右括弧
    decoded_string="${decoded_string//%3B/;}"      # セミコロン
    decoded_string="${decoded_string//%2B/+}"      # プラス記号
    decoded_string="${decoded_string//%2D/-}"      # マイナス記号
    decoded_string="${decoded_string//%2A/*}"      # アスタリスク
    decoded_string="${decoded_string//%3D/=}"      # イコール記号
    decoded_string="${decoded_string//%26/&}"      # アンパサンド
    decoded_string="${decoded_string//%7C/|}"      # パイプ
    decoded_string="${decoded_string//%5C/\\}"     # バックスラッシュ
    decoded_string="${decoded_string//%2F//}"      # フォワードスラッシュ
    
    # 16進エンコーディングを処理（例：%41 = A）
    while [[ $decoded_string =~ %([0-9A-Fa-f]{2}) ]]; do
        local hex_code="${BASH_REMATCH[1]}"
        local char=$(printf "\\x$hex_code")
        decoded_string="${decoded_string//%$hex_code/$char}"
    done
    
    echo "$decoded_string"
}

# 詳細モード用の包括的なSQLインジェクション検出関数
# 二重URLデコード、UTF-8エンコード、より多くのパターンを検出
detect_sql_injection_detailed() {
    local ip="$1"
    local request_url="$2"
    
    # 空のリクエストをスキップ
    if [ -z "$request_url" ]; then
        return 1
    fi
    
    # 大文字小文字を区別しないマッチングのためリクエストを小文字に変換
    local lowercase_request=$(echo "$request_url" | tr '[:upper:]' '[:lower:]')
    
    # 段階的URLデコード処理（詳細モードでのみ実行）
    local decoded_request=$(url_decode "$lowercase_request")
    local double_decoded_request=$(url_decode "$decoded_request")
    local triple_decoded_request=$(url_decode "$double_decoded_request")
    
    # 詳細モード専用の追加SQLインジェクションパターン
    local detailed_patterns=(
        "0x[0-9a-f]+"                    # 16進数値
        "char\s*\(\s*[0-9]+"             # CHAR関数
        "ascii\s*\(\s*"                  # ASCII関数
        "substring\s*\(\s*"              # SUBSTRING関数
        "concat\s*\(\s*"                 # CONCAT関数
        "load_file\s*\(\s*"              # LOAD_FILE関数
        "into\s+outfile"                 # INTO OUTFILE
        "into\s+dumpfile"                # INTO DUMPFILE
        "union\s+all\s+select"           # UNION ALL SELECT
        "order\s+by\s+[0-9]+"            # ORDER BY数値
        "group\s+by\s+[0-9]+"            # GROUP BY数値
        "having\s+[0-9]+"                # HAVING句
        "limit\s+[0-9]+\s*,\s*[0-9]+"    # LIMIT句
        "offset\s+[0-9]+"                # OFFSET句
        "cast\s*\(\s*"                   # CAST関数
        "convert\s*\(\s*"                # CONVERT関数
        "database\s*\(\s*\)"             # DATABASE関数
        "version\s*\(\s*\)"              # VERSION関数
        "user\s*\(\s*\)"                 # USER関数
        "current_user"                   # CURRENT_USER
        "session_user"                   # SESSION_USER
        "system_user"                    # SYSTEM_USER
        "@@version"                      # @@VERSION
        "@@datadir"                      # @@DATADIR
        "@@hostname"                     # @@HOSTNAME
        "information_schema\."           # INFORMATION_SCHEMA
        "mysql\."                        # MySQL system database
        "pg_catalog\."                   # PostgreSQL system catalog
        "sys\."                          # SQL Server system database
        "master\."                       # SQL Server master database
        "msdb\."                         # SQL Server msdb database
        "tempdb\."                       # SQL Server tempdb database
        "xp_cmdshell"                    # SQL Server command execution
        "sp_executesql"                  # SQL Server dynamic SQL
        "openrowset"                     # SQL Server OPENROWSET
        "bulk\s+insert"                  # BULK INSERT
        "exec\s*\(\s*"                   # EXEC function
        "execute\s*\(\s*"                # EXECUTE function
        "declare\s+@"                    # Variable declaration
        "waitfor\s+delay"                # Time delay
        "waitfor\s+time"                 # Time wait
        "benchmark\s*\(\s*[0-9]+"        # MySQL BENCHMARK
        "sleep\s*\(\s*[0-9]+"            # MySQL SLEEP
        "pg_sleep\s*\(\s*[0-9]+"         # PostgreSQL sleep
        "dbms_pipe\.receive_message"     # Oracle time delay
        "utl_inaddr\.get_host_name"      # Oracle DNS lookup
        "extractvalue\s*\(\s*"           # XML functions
        "updatexml\s*\(\s*"              # XML functions
        "xmltype\s*\(\s*"                # Oracle XML
        "and\s+[0-9]+\s*=\s*[0-9]+"     # Tautology
        "or\s+[0-9]+\s*=\s*[0-9]+"      # Tautology
        "and\s+.*\s*like\s*"             # LIKE operator
        "or\s+.*\s*like\s*"              # LIKE operator
        "and\s+.*\s*regexp\s*"           # REGEXP operator
        "or\s+.*\s*regexp\s*"            # REGEXP operator
        "and\s+.*\s*rlike\s*"            # RLIKE operator
        "or\s+.*\s*rlike\s*"             # RLIKE operator
    )
    
    # 全てのパターンを統合（基本パターン + 詳細パターン）
    local all_patterns=("${SQL_INJECTION_PATTERNS[@]}" "${detailed_patterns[@]}")
    
    # 複数レベルのデコードされたリクエストをチェック
    local requests_to_check=(
        "$lowercase_request"
        "$decoded_request"
        "$double_decoded_request"
        "$triple_decoded_request"
    )
    
    local request_labels=(
        "元のリクエスト"
        "URLデコード"
        "二重URLデコード"
        "三重URLデコード"
    )
    
    # 各デコードレベルで全パターンをチェック
    for i in "${!requests_to_check[@]}"; do
        local current_request="${requests_to_check[i]}"
        local current_label="${request_labels[i]}"
        
        # 前のレベルと同じ場合はスキップ（効率化）
        if [ $i -gt 0 ] && [ "$current_request" = "${requests_to_check[$((i-1))]}" ]; then
            continue
        fi
        
        for pattern in "${all_patterns[@]}"; do
            if [[ $current_request =~ $pattern ]]; then
                record_suspicious_ip "$ip" "SQLインジェクション攻撃の可能性 (詳細検出)" "1"
                if [ "$DEBUG_MODE" = true ]; then
                    echo "SQLインジェクション検出 ($current_label): IP $ip - パターン '$pattern' が発見されました: ${current_request:0:100}" >&2
                fi
                return 0  # 疑わしい活動を検出
            fi
        done
    done
    
    return 1  # 疑わしい活動なし
}

# 高速モード用の基本的なSQLインジェクション検出関数
# 基本的なパターンのみをチェックし、URLデコードを簡略化
detect_sql_injection_fast() {
    local ip="$1"
    local request_url="$2"
    
    # 空のリクエストをスキップ
    if [ -z "$request_url" ]; then
        return 1
    fi
    
    # 大文字小文字を区別しないマッチングのためリクエストを小文字に変換
    local lowercase_request=$(echo "$request_url" | tr '[:upper:]' '[:lower:]')
    
    # 高速モード用の基本的なSQLインジェクションパターンのみ
    local fast_patterns=(
        "union.*select"
        "drop.*table"
        "insert.*into"
        "update.*set"
        "delete.*from"
        "script.*alert"
        "javascript:"
        "onload="
        "onerror="
        "%27.*union"     # URLエンコードされた ' union
        "%22.*select"    # URLエンコードされた " select
        "information_schema"
        "waitfor.*delay"
        "benchmark.*("
        "sleep.*("
    )
    
    # 基本的なURLデコードのみ（一回のみ）
    local decoded_request=""
    if [[ "$lowercase_request" =~ %[0-9a-f]{2} ]]; then
        decoded_request=$(url_decode "$lowercase_request")
    else
        decoded_request="$lowercase_request"
    fi
    
    # 元の形式とデコード版をチェック
    for pattern in "${fast_patterns[@]}"; do
        # 元のリクエストをチェック
        if [[ $lowercase_request =~ $pattern ]]; then
            record_suspicious_ip "$ip" "SQLインジェクション攻撃の可能性" "1"
            if [ "$DEBUG_MODE" = true ]; then
                echo "SQLインジェクション検出 (高速): IP $ip - パターン '$pattern' が発見されました: ${request_url:0:100}" >&2
            fi
            return 0  # 疑わしい活動を検出
        fi
        
        # デコードされたリクエストをチェック（元と異なる場合のみ）
        if [ "$decoded_request" != "$lowercase_request" ]; then
            if [[ $decoded_request =~ $pattern ]]; then
                record_suspicious_ip "$ip" "SQLインジェクション攻撃の可能性" "1"
                if [ "$DEBUG_MODE" = true ]; then
                    echo "SQLインジェクション検出 (高速・URLエンコード): IP $ip - パターン '$pattern' がデコード後に発見されました: ${decoded_request:0:100}" >&2
                fi
                return 0  # 疑わしい活動を検出
            fi
        fi
    done
    
    return 1  # 疑わしい活動なし
}

# モードに応じたSQLインジェクション検出の統合関数
detect_sql_injection() {
    local ip="$1"
    local request_url="$2"
    
    if [ "$DETAILED_MODE" = true ]; then
        detect_sql_injection_detailed "$ip" "$request_url"
    else
        detect_sql_injection_fast "$ip" "$request_url"
    fi
}

# ディレクトリトラバーサル攻撃検出変数
declare -A ip_traversal_counts  # 各IPのディレクトリトラバーサル試行回数を格納

# アクセス制御違反検出変数
declare -A ip_access_control_violations  # 各IPのアクセス制御違反回数を格納

# ディレクトリトラバーサル検出パターン
declare -a TRAVERSAL_PATTERNS=(
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
    "\.\.%252f"                  # ..%252f (二重エンコード)
    "%2e%2e%252f"                # %2e%2e%252f (混合エンコード)
    "\.\.%c0%af"                 # ..%c0%af (UTF-8エンコード)
    "%2e%2e%c0%af"               # %2e%2e%c0%af (混合UTF-8)
)

# 詳細モード用の包括的なディレクトリトラバーサル検出関数
# より多くのパターンと三重URLデコードを検出
detect_directory_traversal_detailed() {
    local ip="$1"
    local request_url="$2"
    
    # 空のリクエストをスキップ
    if [ -z "$request_url" ]; then
        return 1
    fi
    
    # 大文字小文字を区別しないマッチングのためリクエストを小文字に変換
    local lowercase_request=$(echo "$request_url" | tr '[:upper:]' '[:lower:]')
    
    # 段階的URLデコード処理（詳細モードでのみ実行）
    local decoded_request=$(url_decode "$lowercase_request")
    local double_decoded_request=$(url_decode "$decoded_request")
    local triple_decoded_request=$(url_decode "$double_decoded_request")
    
    # 詳細モード専用の追加ディレクトリトラバーサルパターン
    local detailed_traversal_patterns=(
        "\.\.%2f.*etc%2fpasswd"          # ../etc/passwd variations
        "\.\.%5c.*windows%5csystem32"    # ..\windows\system32 variations
        "%2e%2e%2f.*boot\.ini"           # ../boot.ini variations
        "\.\..*web\.config"              # ../web.config variations
        "\.\..*\.htaccess"               # ../.htaccess variations
        "%2e%2e.*%2fetc%2fshadow"        # ../etc/shadow variations
        "\.\..*proc%2fversion"           # ../proc/version variations
        "%c0%ae%c0%ae.*etc.*passwd"      # UTF-8 encoded traversal
        "%c1%9c.*windows.*system"        # Invalid UTF-8 traversal
        "file:///.*"                     # File protocol attempts
        "\.\..*\.\..*\.\..*"             # Multiple traversal attempts
        "%252e%252e%252f.*%252e%252e"    # Double encoded multiple traversal
        "\.\.%00"                        # Null byte injection
        "%2e%2e%00"                      # URL encoded null byte
        "\.\.%ff"                        # Invalid byte injection
        "%2e%2e%ff"                      # URL encoded invalid byte
    )
    
    # 全てのパターンを統合（基本パターン + 詳細パターン）
    local all_traversal_patterns=("${TRAVERSAL_PATTERNS[@]}" "${detailed_traversal_patterns[@]}")
    
    # 複数レベルのデコードされたリクエストをチェック
    local requests_to_check=(
        "$lowercase_request"
        "$decoded_request"
        "$double_decoded_request"
        "$triple_decoded_request"
    )
    
    local request_labels=(
        "元のリクエスト"
        "URLデコード"
        "二重URLデコード"
        "三重URLデコード"
    )
    
    # 各デコードレベルで全パターンをチェック
    for i in "${!requests_to_check[@]}"; do
        local current_request="${requests_to_check[i]}"
        local current_label="${request_labels[i]}"
        
        # 前のレベルと同じ場合はスキップ（効率化）
        if [ $i -gt 0 ] && [ "$current_request" = "${requests_to_check[$((i-1))]}" ]; then
            continue
        fi
        
        for pattern in "${all_traversal_patterns[@]}"; do
            if [[ $current_request =~ $pattern ]]; then
                # IPごとの試行回数をカウント
                if [ -z "${ip_traversal_counts[$ip]}" ]; then
                    ip_traversal_counts[$ip]=1
                else
                    ((ip_traversal_counts[$ip]++))
                fi
                
                local count=${ip_traversal_counts[$ip]}
                local risk_level="中リスク"
                if [ $count -ge 5 ]; then
                    risk_level="高リスク"
                fi
                
                record_suspicious_ip "$ip" "ディレクトリトラバーサル攻撃の可能性 (詳細検出・$risk_level・${count}回)" "1"
                if [ "$DEBUG_MODE" = true ]; then
                    echo "ディレクトリトラバーサル検出 ($current_label): IP $ip - パターン '$pattern' が発見されました (${count}回目): ${current_request:0:100}" >&2
                fi
                return 0  # 疑わしい活動を検出
            fi
        done
    done
    
    return 1  # 疑わしい活動なし
}

# 高速モード用の基本的なディレクトリトラバーサル検出関数
# 基本的なパターンのみをチェックし、URLデコードを簡略化
detect_directory_traversal_fast() {
    local ip="$1"
    local request_url="$2"
    
    # 空のリクエストをスキップ
    if [ -z "$request_url" ]; then
        return 1
    fi
    
    # 大文字小文字を区別しないマッチングのためリクエストを小文字に変換
    local lowercase_request=$(echo "$request_url" | tr '[:upper:]' '[:lower:]')
    
    # 高速モード用の基本的なディレクトリトラバーサルパターンのみ
    local fast_traversal_patterns=(
        "\.\./.*"                    # ../
        "\.\.\\.*"                   # ..\
        "%2e%2e%2f"                  # URLエンコードされた../
        "%2e%2e%5c"                  # URLエンコードされた..\
        "\.\.\.\.//.*"               # ....//
        "\.\.\.\.\\\\.*"             # ....\\
        "\.\.%2f"                    # ..%2f
        "%2e%2e/"                    # %2e%2e/
        "\.\.%5c"                    # ..%5c
    )
    
    # 基本的なURLデコードのみ（一回のみ）
    local decoded_request=""
    if [[ "$lowercase_request" =~ %[0-9a-f]{2} ]]; then
        decoded_request=$(url_decode "$lowercase_request")
    else
        decoded_request="$lowercase_request"
    fi
    
    # 元の形式とデコード版をチェック
    for pattern in "${fast_traversal_patterns[@]}"; do
        # 元のリクエストをチェック
        if [[ $lowercase_request =~ $pattern ]]; then
            # IPごとの試行回数をカウント
            if [ -z "${ip_traversal_counts[$ip]}" ]; then
                ip_traversal_counts[$ip]=1
            else
                ((ip_traversal_counts[$ip]++))
            fi
            
            local count=${ip_traversal_counts[$ip]}
            local risk_level="中リスク"
            if [ $count -ge 5 ]; then
                risk_level="高リスク"
            fi
            
            record_suspicious_ip "$ip" "ディレクトリトラバーサル攻撃の可能性 ($risk_level・${count}回)" "1"
            if [ "$DEBUG_MODE" = true ]; then
                echo "ディレクトリトラバーサル検出 (高速): IP $ip - パターン '$pattern' が発見されました (${count}回目): ${request_url:0:100}" >&2
            fi
            return 0  # 疑わしい活動を検出
        fi
        
        # デコードされたリクエストをチェック（元と異なる場合のみ）
        if [ "$decoded_request" != "$lowercase_request" ]; then
            if [[ $decoded_request =~ $pattern ]]; then
                # IPごとの試行回数をカウント
                if [ -z "${ip_traversal_counts[$ip]}" ]; then
                    ip_traversal_counts[$ip]=1
                else
                    ((ip_traversal_counts[$ip]++))
                fi
                
                local count=${ip_traversal_counts[$ip]}
                local risk_level="中リスク"
                if [ $count -ge 5 ]; then
                    risk_level="高リスク"
                fi
                
                record_suspicious_ip "$ip" "ディレクトリトラバーサル攻撃の可能性 ($risk_level・${count}回)" "1"
                if [ "$DEBUG_MODE" = true ]; then
                    echo "ディレクトリトラバーサル検出 (高速・URLエンコード): IP $ip - パターン '$pattern' がデコード後に発見されました (${count}回目): ${decoded_request:0:100}" >&2
                fi
                return 0  # 疑わしい活動を検出
            fi
        fi
    done
    
    return 1  # 疑わしい活動なし
}

# モードに応じたディレクトリトラバーサル検出の統合関数
detect_directory_traversal() {
    local ip="$1"
    local request_url="$2"
    
    if [ "$DETAILED_MODE" = true ]; then
        detect_directory_traversal_detailed "$ip" "$request_url"
    else
        detect_directory_traversal_fast "$ip" "$request_url"
    fi
}

# 時間ベースの計算のためタイムスタンプをUnix時間に変換する関数
timestamp_to_unix() {
    local timestamp="$1"
    
    # Apacheタイムスタンプ形式 [01/Jan/2024:12:00:00 +0000] をUnix時間に変換
    # bash組み込み機能を使用して括弧とタイムゾーンを削除（sedより高速）
    local clean_timestamp="$timestamp"
    clean_timestamp="${clean_timestamp#[}"  # 先頭の[を削除
    clean_timestamp="${clean_timestamp%]*}" # 末尾の]以降を削除
    
    # タイムゾーン部分を削除（スペース + タイムゾーン記号）
    clean_timestamp="${clean_timestamp% *}"  # 最後のスペース以降を削除
    
    # "01/Jan/2024:12:00:00" から "2024-01-01 12:00:00" 形式に変換
    # タイムスタンプコンポーネントを解析
    if [[ $clean_timestamp =~ ^([0-9]{2})/([A-Za-z]{3})/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})$ ]]; then
        local day="${BASH_REMATCH[1]}"
        local month_name="${BASH_REMATCH[2]}"
        local year="${BASH_REMATCH[3]}"
        local hour="${BASH_REMATCH[4]}"
        local minute="${BASH_REMATCH[5]}"
        local second="${BASH_REMATCH[6]}"
        
        # 月名を数字に変換
        case "$month_name" in
            Jan) month="01" ;;
            Feb) month="02" ;;
            Mar) month="03" ;;
            Apr) month="04" ;;
            May) month="05" ;;
            Jun) month="06" ;;
            Jul) month="07" ;;
            Aug) month="08" ;;
            Sep) month="09" ;;
            Oct) month="10" ;;
            Nov) month="11" ;;
            Dec) month="12" ;;
            *) echo "0"; return ;;
        esac
        
        # ISO 8601形式にフォーマットしてUnixタイムスタンプに変換
        local iso_timestamp="${year}-${month}-${day} ${hour}:${minute}:${second}"
        date -d "$iso_timestamp" +%s 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# 高頻度アクセスパターンを検出する関数
# 5分間のスライディングウィンドウで100回以上のリクエストを持つIPを検出
# 最適化: 大容量データセットでのメモリ使用量削減とパフォーマンス向上
detect_high_frequency() {
    local ip="$1"
    local unix_timestamp="$2"
    
    # 最適化されたデータ構造で新しいIPのアクセス履歴を初期化
    if [ -z "${ip_access_history[$ip]}" ]; then
        ip_access_history[$ip]="$unix_timestamp"
        ip_access_counts[$ip]=1
    else
        # 新しいタイムスタンプを効率的に追加
        ip_access_history[$ip]="${ip_access_history[$ip]} $unix_timestamp"
        ((ip_access_counts[$ip]++))
    fi
    
    # 早期最適化: 十分なリクエストがある場合のみスライディングウィンドウを処理
    # これにより低活動IPの高コストな配列操作を回避
    if [ "${ip_access_counts[$ip]}" -lt 50 ]; then
        return 1  # 疑わしいとするには十分なリクエストがない
    fi
    
    # スライディングウィンドウ最適化: 最近のタイムスタンプのみを保持
    local window_start=$((unix_timestamp - 300))  # 5分間 = 300秒
    local access_times=(${ip_access_history[$ip]})
    local valid_accesses=()
    local count_in_window=0
    
    # Optimized filtering: Process from end to beginning (most recent first)
    # This allows early termination when we hit old timestamps
    local i
    for ((i=${#access_times[@]}-1; i>=0; i--)); do
        local timestamp="${access_times[i]}"
        if [ "$timestamp" -ge "$window_start" ]; then
            valid_accesses=("$timestamp" "${valid_accesses[@]}")
            ((count_in_window++))
        else
            # All remaining timestamps are older, break early
            break
        fi
    done
    
    # Memory optimization: Update access history with only valid timestamps
    # Keep maximum of MAX_ACCESS_HISTORY timestamps to prevent unbounded growth
    if [ ${#valid_accesses[@]} -gt $MAX_ACCESS_HISTORY ]; then
        ip_access_history[$ip]="${valid_accesses[*]:0:$MAX_ACCESS_HISTORY}"
    else
        ip_access_history[$ip]="${valid_accesses[*]}"
    fi
    
    # Update count efficiently
    ip_access_counts[$ip]="$count_in_window"
    
    # Reduced debug output for performance
    if [ "$DEBUG_MODE" = true ] && [ "$count_in_window" -gt 80 ]; then
        echo "DEBUG: IP $ip - Count in window: $count_in_window" >&2
    fi
    
    # Check if access count exceeds threshold (100 requests in 5 minutes)
    if [ "$count_in_window" -ge 100 ]; then
        record_suspicious_ip "$ip" "高頻度アクセス" "$count_in_window"
        if [ "$DEBUG_MODE" = true ]; then
            echo "HIGH FREQUENCY DETECTED: IP $ip with $count_in_window requests in 5-minute window" >&2
        fi
        return 0  # Suspicious activity detected
    fi
    
    return 1  # No suspicious activity
}

# 400系エラー検出用のデータ構造
declare -A ip_4xx_counts        # 各IPの400系エラー総数
declare -A ip_4xx_history       # 各IPの400系エラー履歴（タイムスタンプ付き）
declare -A ip_4xx_types         # 各IPの400系エラータイプ別カウント

# 400系エラーコードと対応する攻撃タイプのマッピング
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

# 400系エラーコード別の閾値設定
declare -A ERROR_THRESHOLDS=(
    ["404"]=10      # 従来の404エラー検出
    ["401"]=20      # 認証失敗検出（10分間）
    ["403"]=20      # 認証失敗検出（10分間）
    ["default"]=50  # その他の400系エラー（5分間）
)

# 包括的な400系エラー検出機能
# 400-499の範囲のすべてのクライアントエラーを検出し、攻撃タイプを推定
detect_4xx_errors() {
    local ip="$1"
    local status_code="$2"
    local unix_timestamp="$3"
    
    # 400系エラーかどうかをチェック
    if [[ ! "$status_code" =~ ^4[0-9][0-9]$ ]]; then
        return 1  # 400系エラーではない
    fi
    
    # IPの400系エラー履歴を初期化
    if [ -z "${ip_4xx_history[$ip]}" ]; then
        ip_4xx_history[$ip]=""
        ip_4xx_counts[$ip]=0
        ip_4xx_types[$ip]=""
    fi
    
    # 400系エラー総数をインクリメント
    ((ip_4xx_counts[$ip]++))
    
    # タイムスタンプ付きで履歴に追加
    if [ -n "$unix_timestamp" ]; then
        if [ -n "${ip_4xx_history[$ip]}" ]; then
            ip_4xx_history[$ip]="${ip_4xx_history[$ip]} ${unix_timestamp}:${status_code}"
        else
            ip_4xx_history[$ip]="${unix_timestamp}:${status_code}"
        fi
    fi
    
    # エラータイプ別カウントを更新
    local current_types="${ip_4xx_types[$ip]}"
    if [[ "$current_types" =~ ${status_code}:([0-9]+) ]]; then
        # 既存のエラータイプのカウントを更新
        local current_count="${BASH_REMATCH[1]}"
        ((current_count++))
        ip_4xx_types[$ip]="${current_types/${status_code}:${BASH_REMATCH[1]}/${status_code}:${current_count}}"
    else
        # 新しいエラータイプを追加
        if [ -n "$current_types" ]; then
            ip_4xx_types[$ip]="${current_types} ${status_code}:1"
        else
            ip_4xx_types[$ip]="${status_code}:1"
        fi
    fi
    
    # 特定エラーコードの個別閾値チェック
    local specific_threshold="${ERROR_THRESHOLDS[$status_code]}"
    if [ -n "$specific_threshold" ]; then
        # 特定エラーコードのカウントを取得
        local specific_count=0
        if [[ "${ip_4xx_types[$ip]}" =~ ${status_code}:([0-9]+) ]]; then
            specific_count="${BASH_REMATCH[1]}"
        fi
        
        # 特定エラーコードの閾値チェック
        if [ "$specific_count" -ge "$specific_threshold" ]; then
            local attack_type="${ERROR_ATTACK_TYPES[$status_code]:-"400系エラー攻撃"}"
            
            # 401/403の場合は時間窓をチェック（10分間）
            if [ "$status_code" = "401" ] || [ "$status_code" = "403" ]; then
                local count_in_window=$(count_errors_in_window "$ip" "$status_code" "$unix_timestamp" 600)
                if [ "$count_in_window" -ge "$specific_threshold" ]; then
                    record_suspicious_ip "$ip" "$attack_type" "$count_in_window"
                    if [ "$DEBUG_MODE" = true ]; then
                        echo "4XX SPECIFIC DETECTED: IP $ip - $status_code errors: $count_in_window in 10-minute window" >&2
                    fi
                fi
            else
                record_suspicious_ip "$ip" "$attack_type" "$specific_count"
                if [ "$DEBUG_MODE" = true ]; then
                    echo "4XX SPECIFIC DETECTED: IP $ip - $status_code errors: $specific_count total" >&2
                fi
            fi
        fi
    fi
    
    # 5分間のスライディングウィンドウで400系エラー総数をチェック
    if [ -n "$unix_timestamp" ]; then
        local count_in_window=$(count_errors_in_window "$ip" "all" "$unix_timestamp" 300)
        local default_threshold="${ERROR_THRESHOLDS["default"]}"
        
        if [ "$count_in_window" -ge "$default_threshold" ]; then
            # 攻撃タイプを推定
            local attack_classification=$(classify_4xx_attack "$ip")
            record_suspicious_ip "$ip" "大量の400系エラー - $attack_classification" "$count_in_window"
            if [ "$DEBUG_MODE" = true ]; then
                echo "4XX BULK DETECTED: IP $ip - $count_in_window 4xx errors in 5-minute window ($attack_classification)" >&2
            fi
            return 0
        fi
    fi
    
    return 1  # 閾値未満
}

# 指定された時間窓内のエラー数をカウントする補助関数
count_errors_in_window() {
    local ip="$1"
    local error_code="$2"  # "all" for all 4xx errors, specific code for specific errors
    local current_time="$3"
    local window_seconds="$4"
    
    local window_start=$((current_time - window_seconds))
    local history="${ip_4xx_history[$ip]}"
    local count=0
    
    if [ -z "$history" ]; then
        echo 0
        return
    fi
    
    # 履歴をスペースで分割して処理
    local entries=($history)
    for entry in "${entries[@]}"; do
        if [[ "$entry" =~ ^([0-9]+):([0-9]+)$ ]]; then
            local timestamp="${BASH_REMATCH[1]}"
            local code="${BASH_REMATCH[2]}"
            
            # 時間窓内かチェック
            if [ "$timestamp" -ge "$window_start" ]; then
                # 全ての4xxエラーまたは特定のエラーコードをカウント
                if [ "$error_code" = "all" ] || [ "$error_code" = "$code" ]; then
                    ((count++))
                fi
            fi
        fi
    done
    
    echo "$count"
}

# 400系エラーパターンから攻撃タイプを分類する関数
classify_4xx_attack() {
    local ip="$1"
    local types="${ip_4xx_types[$ip]}"
    
    if [ -z "$types" ]; then
        echo "スキャン/攻撃の可能性"
        return
    fi
    
    # エラータイプを解析
    local type_array=($types)
    local unique_types=0
    local dominant_type=""
    local max_count=0
    
    for type_entry in "${type_array[@]}"; do
        if [[ "$type_entry" =~ ^([0-9]+):([0-9]+)$ ]]; then
            local code="${BASH_REMATCH[1]}"
            local count="${BASH_REMATCH[2]}"
            
            ((unique_types++))
            
            if [ "$count" -gt "$max_count" ]; then
                max_count="$count"
                dominant_type="$code"
            fi
        fi
    done
    
    # 攻撃タイプを分類
    if [ "$unique_types" -ge 5 ]; then
        echo "複合的な400系エラー攻撃"
    elif [ -n "$dominant_type" ] && [ -n "${ERROR_ATTACK_TYPES[$dominant_type]}" ]; then
        echo "${ERROR_ATTACK_TYPES[$dominant_type]}"
    else
        echo "スキャン/攻撃の可能性"
    fi
}

# 後方互換性のための404エラー検出関数（detect_4xx_errorsに統合済み）
detect_404_errors() {
    local ip="$1"
    local status_code="$2"
    
    # 新しい包括的な4xx検出機能を呼び出し
    detect_4xx_errors "$ip" "$status_code" ""
}

# 後方互換性のための認証失敗検出関数（detect_4xx_errorsに統合済み）
detect_auth_failures() {
    local ip="$1"
    local status_code="$2"
    local unix_timestamp="$3"
    
    # 新しい包括的な4xx検出機能を呼び出し
    detect_4xx_errors "$ip" "$status_code" "$unix_timestamp"
}

# IP geolocation cache for performance optimization
declare -A ip_country_cache

# Function to convert 2-letter country code to full country name
# Based on ISO 3166-1 alpha-2 standard with comprehensive mapping for all 195 UN member countries
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


# Uses external API services with fallback to whois command
# OPTIMIZED: Added caching and reduced timeout for better performance
get_country_info() {
    local ip="$1"
    
    # Check cache first for performance optimization
    if [ -n "${ip_country_cache[$ip]}" ]; then
        ((performance_metrics["cache_hits"]++))
        echo "${ip_country_cache[$ip]}"
        return
    fi
    
    # キャッシュミス
    ((performance_metrics["cache_misses"]++))
    
    local country=""
    
    # Skip invalid IP addresses
    if [ -z "$ip" ] || [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        country="不明"
        ip_country_cache[$ip]="$country"
        echo "$country"
        return
    fi
    
    # Quick validation of IP address ranges (0-255 for each octet)
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
            country="不明"
            ip_country_cache[$ip]="$country"
            echo "$country"
            return
        fi
    done
    
    # Skip private IP addresses (they won't have meaningful geolocation)
    if [[ $ip =~ ^10\. ]] || [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ $ip =~ ^127\. ]] || [[ $ip =~ ^169\.254\. ]] || [[ $ip =~ ^224\. ]]; then
        country="プライベートIP"
        ip_country_cache[$ip]="$country"
        echo "$country"
        return
    fi
    
    # Check if curl is available
    if ! command -v curl >/dev/null 2>&1; then
        country="不明 (curl未利用可能)"
        ip_country_cache[$ip]="$country"
        echo "$country"
        return
    fi
    
    # Method 1: Try ip-api.com (free service, no API key required)
    # Reduced timeout for better performance
    country=$(timeout 8 curl -s --connect-timeout 3 --max-time 5 --retry 0 "http://ip-api.com/line/$ip?fields=country" 2>/dev/null)
    local curl_exit_code=$?
    
    # Check if ip-api.com returned valid result
    if [ $curl_exit_code -eq 0 ] && [ -n "$country" ] && [ "$country" != "fail" ] && [ "$country" != "" ] && [ ${#country} -lt 100 ]; then
        # Sanitize the result (remove any control characters) - bash optimized
        country=$(echo "$country" | tr -d '\r\n\t\x00-\x1f\x7f-\x9f')
        if [ -n "$country" ]; then
            ip_country_cache[$ip]="$country"
            echo "$country"
            return
        fi
    fi
    
    # Method 2: Try ipinfo.io (free service with rate limits)
    # Reduced timeout for better performance
    country=$(timeout 8 curl -s --connect-timeout 3 --max-time 5 --retry 0 "https://ipinfo.io/$ip/country" 2>/dev/null | tr -d '\n\r\t')
    curl_exit_code=$?
    
    # Check if ipinfo.io returned valid result (2-letter country code)
    # Also check that it's not a JSON error response
    if [ $curl_exit_code -eq 0 ] && [ -n "$country" ] && [[ $country =~ ^[A-Z]{2}$ ]] && [[ ! $country =~ ^\{ ]]; then
        # Convert country code to full name using comprehensive mapping
        country=$(convert_country_code "$country")
        ip_country_cache[$ip]="$country"
        echo "$country"
        return
    fi
    
    # Skip additional API calls for performance in large datasets
    # Method 3 and 4 removed to improve performance
    
    # All methods failed, return unknown
    country="不明"
    ip_country_cache[$ip]="$country"
    echo "$country"
}

# Function to record suspicious IP addresses
record_suspicious_ip() {
    local ip="$1"
    local reason="$2"
    
    # パフォーマンス測定
    ((performance_metrics["detection_count"]++))
    local count="$3"
    
    # If count is empty, default to 1
    if [ -z "$count" ]; then
        count="1"
    fi
    
    # Record in the traditional way for backward compatibility
    if [ -n "$count" ]; then
        suspicious_ips[$ip]="$reason:${count}回"
    else
        suspicious_ips[$ip]="$reason"
    fi
    
    # Also record in the comprehensive array for integrated reporting
    local detection_entry="$ip|$reason|$count"
    all_suspicious_detections+=("$detection_entry")
}

# Function to merge duplicate IP addresses and their detection reasons
# This function integrates results from both access_log and error_log analysis
merge_suspicious_ips() {
    local -A merged_ips
    local -A ip_priorities
    local -A ip_counts
    local -A ip_reasons
    local -A ip_source_logs  # Track which log sources detected each IP
    
    # Define priority levels for different threat types (higher number = higher priority)
    local -A threat_priorities=(
        ["SQLインジェクション攻撃の可能性"]=10
        ["WAF攻撃ブロック - ModSecurity"]=9
        ["繰り返される認証失敗 - ブルートフォースの可能性"]=8
        ["認証失敗 - ブルートフォースの可能性"]=8
        ["複合的な400系エラー攻撃"]=8
        ["高頻度アクセス"]=7
        ["大量の400系エラー - スキャン/攻撃の可能性"]=7
        ["大量の400系エラー - 複合的な400系エラー攻撃"]=7
        ["大量の400系エラー - 不正リクエスト攻撃"]=6
        ["大量の400系エラー - アクセス制御回避試行"]=6
        ["大量の400系エラー - リソース探索/偵察活動"]=6
        ["複数の404エラー - 偵察の可能性"]=6
        ["存在しないファイルへのアクセス - 偵察の可能性"]=6
        ["リソース探索/偵察活動"]=6
        ["不正リクエスト攻撃"]=5
        ["アクセス制御回避試行"]=5
        ["権限拒否 - 権限昇格攻撃の可能性"]=5
        ["不正なスクリプト実行試行"]=5
        ["HTTPメソッド攻撃"]=4
        ["ペイロード攻撃"]=4
        ["URI長攻撃"]=4
        ["不正なURI - 攻撃の可能性"]=4
        ["リクエスト失敗 - HTTP攻撃の可能性"]=4
        ["レート制限回避試行"]=3
        ["タイムアウト攻撃"]=3
        ["競合状態攻撃"]=3
        ["コンテンツネゴシエーション攻撃"]=3
        ["メディアタイプ攻撃"]=3
        ["削除済みリソース探索"]=3
        ["SSL/TLS攻撃の可能性"]=3
        ["アクセス制御違反"]=3
        ["error_log異常パターン検出"]=2
    )
    
    if [ "$VERBOSE_OUTPUT" = true ]; then
        echo "統合レポート: access_logとerror_logの解析結果をマージ中..." >&2
    fi
    
    # Process all detections from the comprehensive array
    local total_detections=${#all_suspicious_detections[@]}
    local processed_detections=0
    
    for detection in "${all_suspicious_detections[@]}"; do
        if [ -z "$detection" ]; then
            continue
        fi
        
        IFS='|' read -r ip reason count <<< "$detection"
        ((processed_detections++))
        
        # Skip empty entries
        if [ -z "$ip" ] || [ -z "$reason" ]; then
            continue
        fi
        
        # Set default count if empty
        if [ -z "$count" ]; then
            count="0"
        fi
        
        # Determine log source based on threat type
        local log_source="access_log"
        case "$reason" in
            "WAF攻撃ブロック - ModSecurity"|"存在しないファイルへのアクセス - 偵察の可能性"|"権限拒否 - 権限昇格攻撃の可能性"|"不正なスクリプト実行試行"|"不正なURI - 攻撃の可能性"|"リクエスト失敗 - HTTP攻撃の可能性"|"SSL/TLS攻撃の可能性"|"アクセス制御違反"|"error_log異常パターン検出")
                log_source="error_log"
                ;;
        esac
        
        # Get priority for this threat type
        local current_priority="${threat_priorities[$reason]:-1}"
        
        # If IP already exists in merged results
        if [ -n "${merged_ips[$ip]}" ]; then
            local existing_reasons="${ip_reasons[$ip]}"
            local existing_priority="${ip_priorities[$ip]}"
            local existing_count="${ip_counts[$ip]}"
            local existing_sources="${ip_source_logs[$ip]}"
            
            # Check if this reason is already included
            if [[ "$existing_reasons" != *"$reason"* ]]; then
                # Add new reason to existing reasons with intelligent merging
                if [ "$current_priority" -gt "$existing_priority" ]; then
                    # New reason has higher priority, make it primary
                    merged_ips[$ip]="$reason"
                    ip_reasons[$ip]="$reason + $existing_reasons"
                    ip_priorities[$ip]="$current_priority"
                else
                    # Existing reason has higher priority, append new reason
                    ip_reasons[$ip]="$existing_reasons + $reason"
                fi
                
                # Update source logs
                if [[ "$existing_sources" != *"$log_source"* ]]; then
                    ip_source_logs[$ip]="$existing_sources,$log_source"
                fi
            fi
            
            # Update count (take maximum for better threat assessment)
            if [ "$count" -gt "$existing_count" ]; then
                ip_counts[$ip]="$count"
            fi
        else
            # New IP, add to merged results
            merged_ips[$ip]="$reason"
            ip_priorities[$ip]="$current_priority"
            ip_counts[$ip]="$count"
            ip_reasons[$ip]="$reason"
            ip_source_logs[$ip]="$log_source"
        fi
    done
    
    if [ "$VERBOSE_OUTPUT" = true ]; then
        echo "統合完了: ${processed_detections}件の検出結果から${#merged_ips[@]}個のユニークIPを特定" >&2
    fi
    
    # Update suspicious_ips with merged results including source information
    suspicious_ips=()
    for ip in "${!merged_ips[@]}"; do
        local merged_reason="${ip_reasons[$ip]}"
        local merged_count="${ip_counts[$ip]}"
        local source_info="${ip_source_logs[$ip]}"
        
        # Format the reason with source information for comprehensive reporting
        local formatted_reason="$merged_reason"
        if [[ "$source_info" == *","* ]]; then
            # Multiple sources detected this IP
            formatted_reason="$merged_reason [統合検出: access_log+error_log]"
        elif [[ "$source_info" == "error_log" ]]; then
            formatted_reason="$merged_reason [error_log検出]"
        else
            formatted_reason="$merged_reason [access_log検出]"
        fi
        
        if [ "$merged_count" != "0" ]; then
            suspicious_ips[$ip]="$formatted_reason:${merged_count}回"
        else
            suspicious_ips[$ip]="$formatted_reason"
        fi
    done
    
    if [ "$VERBOSE_OUTPUT" = true ]; then
        echo "重複IPアドレスのマージ完了" >&2
    fi
}

# Function to sort integrated results by priority order
# Returns sorted list of IPs based on threat priority and occurrence count
# Enhanced to handle integrated detection sources and multiple threat types
sort_by_priority() {
    local temp_file=$(mktemp)
    
    # Define priority levels for sorting (higher number = higher priority)
    local -A threat_priorities=(
        ["SQLインジェクション攻撃の可能性"]=10
        ["WAF攻撃ブロック - ModSecurity"]=9
        ["繰り返される認証失敗 - ブルートフォースの可能性"]=8
        ["認証失敗 - ブルートフォースの可能性"]=8
        ["複合的な400系エラー攻撃"]=8
        ["高頻度アクセス"]=7
        ["大量の400系エラー - スキャン/攻撃の可能性"]=7
        ["大量の400系エラー - 複合的な400系エラー攻撃"]=7
        ["大量の400系エラー - 不正リクエスト攻撃"]=6
        ["大量の400系エラー - アクセス制御回避試行"]=6
        ["大量の400系エラー - リソース探索/偵察活動"]=6
        ["複数の404エラー - 偵察の可能性"]=6
        ["存在しないファイルへのアクセス - 偵察の可能性"]=6
        ["リソース探索/偵察活動"]=6
        ["不正リクエスト攻撃"]=5
        ["アクセス制御回避試行"]=5
        ["権限拒否 - 権限昇格攻撃の可能性"]=5
        ["不正なスクリプト実行試行"]=5
        ["HTTPメソッド攻撃"]=4
        ["ペイロード攻撃"]=4
        ["URI長攻撃"]=4
        ["不正なURI - 攻撃の可能性"]=4
        ["リクエスト失敗 - HTTP攻撃の可能性"]=4
        ["レート制限回避試行"]=3
        ["タイムアウト攻撃"]=3
        ["競合状態攻撃"]=3
        ["コンテンツネゴシエーション攻撃"]=3
        ["メディアタイプ攻撃"]=3
        ["削除済みリソース探索"]=3
        ["SSL/TLS攻撃の可能性"]=3
        ["アクセス制御違反"]=3
        ["error_log異常パターン検出"]=2
    )
    
    # Prepare data for sorting
    for ip in "${!suspicious_ips[@]}"; do
        local reason="${suspicious_ips[$ip]}"
        local count="0"
        local base_reason="$reason"
        local priority="1"
        local source_bonus=0
        
        # Extract count from reason if present
        if [[ "$reason" =~ ^(.+):([0-9]+)回$ ]]; then
            base_reason="${BASH_REMATCH[1]}"
            count="${BASH_REMATCH[2]}"
        fi
        
        # Add priority bonus for integrated detections (more reliable)
        if [[ "$base_reason" =~ \[統合検出:.*\] ]]; then
            source_bonus=1  # Slight bonus for integrated detections
        fi
        
        # Remove source information for priority calculation
        local clean_reason=$(echo "$base_reason" | sed 's/ \[.*検出.*\]$//')
        
        # Get priority for primary threat type (first part if multiple reasons)
        local primary_reason="$clean_reason"
        if [[ "$clean_reason" =~ ^([^+]+) ]]; then
            primary_reason="${BASH_REMATCH[1]}"
        fi
        
        # For merged reasons, use the highest priority among all reasons
        local max_priority=1
        if [[ "$clean_reason" =~ \+ ]]; then
            # Split by + and find highest priority
            IFS=' + ' read -ra reason_parts <<< "$clean_reason"
            for reason_part in "${reason_parts[@]}"; do
                # Trim whitespace
                reason_part=$(echo "$reason_part" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                local part_priority="${threat_priorities[$reason_part]:-1}"
                if [ "$part_priority" -gt "$max_priority" ]; then
                    max_priority="$part_priority"
                fi
            done
            priority="$max_priority"
        else
            priority="${threat_priorities[$primary_reason]:-1}"
        fi
        
        # Apply source bonus
        priority=$((priority + source_bonus))
        
        # Write to temp file: priority|count|ip|reason for sorting
        # Use padded numbers for proper sorting
        printf "%02d|%06d|%s|%s\n" "$priority" "$count" "$ip" "$reason" >> "$temp_file"
    done
    
    # Sort by priority (descending), then by count (descending), then by IP (ascending for consistency)
    sort -t'|' -k1,1nr -k2,2nr -k3,3 "$temp_file" | while IFS='|' read -r priority count ip reason; do
        # Remove padding and output
        priority=$((10#$priority))
        count=$((10#$count))
        echo "$priority|$count|$ip|$reason"
    done
    
    # Clean up
    rm -f "$temp_file"
}

# Function to generate integrated report with access_log and error_log analysis results
# Merges duplicate IP addresses and sorts by priority order
# Includes error_log-derived threat information in report output
generate_integrated_report() {
    local analysis_timestamp="$1"
    local log_type="$2"
    
    # Determine log type description for report
    local log_type_description=""
    case "$log_type" in
        "access_log")
            log_type_description="access_log"
            ;;
        "error_log")
            log_type_description="error_log"
            ;;
        "ssl_request_log")
            log_type_description="ssl_request_log"
            ;;
        "ssl_access_log")
            log_type_description="ssl_access_log"
            ;;
        "mixed_access_primary"|"mixed_error_primary")
            log_type_description="access_log + error_log (混在ログ)"
            ;;
        *)
            log_type_description="不明なログタイプ"
            ;;
    esac
    
    echo ""
    echo "========================================"
    echo "HTTPd ログ解析レポート"
    echo "========================================"
    echo "解析実行時刻: $analysis_timestamp"
    echo "解析対象: $log_type_description"
    echo ""
    
    # Merge duplicate IP addresses and their detection reasons
    merge_suspicious_ips
    
    # Check if any suspicious IPs were detected after merging
    if [ ${#suspicious_ips[@]} -eq 0 ]; then
        echo "疑わしい活動は検出されませんでした。"
        echo "  - ${log_type_description}を解析しましたが、脅威は検出されませんでした。"
        echo ""
        return 0
    fi
    
    echo "疑わしいIPアドレスが検出されました (${log_type_description} 解析結果):"
    echo "----------------------------------------"
    
    # Display threat summary by category and source
    echo "検出された脅威の概要:"
    local -A threat_summary
    local -A source_summary
    local access_log_threats=0
    local error_log_threats=0
    local integrated_threats=0
    
    for ip in "${!suspicious_ips[@]}"; do
        local reason="${suspicious_ips[$ip]}"
        local base_reason="$reason"
        
        # Extract base reason (remove count and source info)
        if [[ "$reason" =~ ^(.+):([0-9]+)回$ ]]; then
            base_reason="${BASH_REMATCH[1]}"
        fi
        
        # Remove source information for threat categorization
        base_reason=$(echo "$base_reason" | sed 's/ \[.*検出\]$//')
        
        # Count threat sources
        if [[ "$reason" =~ \[統合検出:.*\] ]]; then
            ((integrated_threats++))
        elif [[ "$reason" =~ \[error_log検出\] ]]; then
            ((error_log_threats++))
        else
            ((access_log_threats++))
        fi
        
        # Count each threat type
        if [[ "$base_reason" =~ ^([^+]+) ]]; then
            local primary_threat="${BASH_REMATCH[1]}"
            threat_summary[$primary_threat]=$((${threat_summary[$primary_threat]:-0} + 1))
        else
            threat_summary[$base_reason]=$((${threat_summary[$base_reason]:-0} + 1))
        fi
    done
    
    # Display source summary - simplified for single log files
    if [[ "$log_type" == "mixed_access_primary" || "$log_type" == "mixed_error_primary" ]]; then
        echo "  ログソース別検出数:"
        echo "    - access_log単独検出: ${access_log_threats}件"
        echo "    - error_log単独検出: ${error_log_threats}件"
        echo "    - 統合検出 (両ログ): ${integrated_threats}件"
    else
        local total_threats=$((access_log_threats + error_log_threats + integrated_threats))
        echo "  ログソース別検出数: ${total_threats}件"
    fi
    echo ""
    
    # Display threat summary sorted by priority
    echo "  脅威タイプ別検出数 (優先度順):"
    local -A threat_priorities=(
        ["SQLインジェクション攻撃の可能性"]=10
        ["WAF攻撃ブロック - ModSecurity"]=9
        ["繰り返される認証失敗 - ブルートフォースの可能性"]=8
        ["認証失敗 - ブルートフォースの可能性"]=8
        ["複合的な400系エラー攻撃"]=8
        ["高頻度アクセス"]=7
        ["大量の400系エラー - スキャン/攻撃の可能性"]=7
        ["大量の400系エラー - 複合的な400系エラー攻撃"]=7
        ["大量の400系エラー - 不正リクエスト攻撃"]=6
        ["大量の400系エラー - アクセス制御回避試行"]=6
        ["大量の400系エラー - リソース探索/偵察活動"]=6
        ["複数の404エラー - 偵察の可能性"]=6
        ["存在しないファイルへのアクセス - 偵察の可能性"]=6
        ["リソース探索/偵察活動"]=6
        ["不正リクエスト攻撃"]=5
        ["アクセス制御回避試行"]=5
        ["権限拒否 - 権限昇格攻撃の可能性"]=5
        ["不正なスクリプト実行試行"]=5
        ["HTTPメソッド攻撃"]=4
        ["ペイロード攻撃"]=4
        ["URI長攻撃"]=4
        ["不正なURI - 攻撃の可能性"]=4
        ["リクエスト失敗 - HTTP攻撃の可能性"]=4
        ["レート制限回避試行"]=3
        ["タイムアウト攻撃"]=3
        ["競合状態攻撃"]=3
        ["コンテンツネゴシエーション攻撃"]=3
        ["メディアタイプ攻撃"]=3
        ["削除済みリソース探索"]=3
        ["SSL/TLS攻撃の可能性"]=3
        ["アクセス制御違反"]=3
        ["error_log異常パターン検出"]=2
    )
    
    # Create sorted list of threats by priority
    local temp_file=$(mktemp)
    for threat_type in "${!threat_summary[@]}"; do
        local priority="${threat_priorities[$threat_type]:-1}"
        echo "$priority|$threat_type|${threat_summary[$threat_type]}" >> "$temp_file"
    done
    
    # Display sorted threat summary
    sort -t'|' -k1,1nr "$temp_file" | while IFS='|' read -r priority threat_type count; do
        local priority_label=""
        case "$priority" in
            10|9|8) priority_label="[高]" ;;
            7|6|5) priority_label="[中]" ;;
            *) priority_label="[低]" ;;
        esac
        echo "    $priority_label $threat_type: ${count}件"
    done
    rm -f "$temp_file"
    echo ""
    
    # Display detailed results sorted by priority
    echo "検出された疑わしい活動の詳細 (優先度順):"
    echo ""
    printf "%-16s %-8s %-60s %-20s\n" "IPアドレス" "回数" "理由・検出元" "国名"
    echo "--------------------------------------------------------------------------------------------------------"
    
    # Get sorted results by priority
    sort_by_priority | while IFS='|' read -r priority count ip reason; do
        # Get country information for the IP address
        if [ "$ENABLE_GEO_LOOKUP" = true ]; then
            echo "地理位置検索中: $ip..." >&2
        fi
        local country=""
        if [ "$ENABLE_GEO_LOOKUP" = false ]; then
            country="N/A"
        else
            country=$(get_country_info "$ip")
        fi
        
        # Format count display
        local count_display=""
        if [ "$count" != "0" ]; then
            count_display="${count}回"
        else
            count_display="-"
        fi
        
        # Truncate long reasons for display but keep source info
        local display_reason="$reason"
        if [ ${#reason} -gt 58 ]; then
            # Try to preserve source information when truncating
            if [[ "$reason" =~ (.*)\s+\[.*検出.*\]$ ]]; then
                local main_part="${BASH_REMATCH[1]}"
                local source_part="${reason##*[}"
                source_part="[${source_part}"
                local available_space=$((55 - ${#source_part}))
                if [ ${#main_part} -gt $available_space ]; then
                    display_reason="${main_part:0:$available_space}... $source_part"
                else
                    display_reason="$main_part $source_part"
                fi
            else
                display_reason="${reason:0:55}..."
            fi
        fi
        
        # Display formatted result with priority indicator
        local priority_indicator=""
        case "$priority" in
            10|9|8) priority_indicator="[高]" ;;
            7|6|5) priority_indicator="[中]" ;;
            *) priority_indicator="[低]" ;;
        esac
        
        printf "%-16s %-8s %-60s %-20s\n" "$ip" "$count_display" "$priority_indicator $display_reason" "$country"
    done
    
    echo "--------------------------------------------------------------------------------------------------------"
    echo ""
    echo "優先度・検出元説明:"
    echo "  [高] - 即座に対応が必要な重大な脅威 (SQLインジェクション、WAF攻撃ブロック、ブルートフォース)"
    echo "  [中] - 監視が必要な中程度の脅威 (高頻度アクセス、偵察活動、権限昇格試行)"
    echo "  [低] - 注意が必要な軽微な脅威 (アクセス制御違反、その他の異常パターン)"
    echo ""
    
    # Display source information based on log type
    case "$log_type" in
        "access_log")
            echo "  [access_log検出] - アクセスログから検出された脅威"
            ;;
        "error_log")
            echo "  [error_log検出] - エラーログから検出された脅威"
            ;;
        "ssl_request_log")
            echo "  [ssl_request_log検出] - SSL/TLSリクエストログから検出された脅威"
            ;;
        "ssl_access_log")
            echo "  [ssl_access_log検出] - SSL/TLSアクセスログから検出された脅威"
            ;;
        "mixed_access_primary"|"mixed_error_primary")
            echo "  [access_log検出] - アクセスログから検出された脅威"
            echo "  [error_log検出] - エラーログから検出された脅威"
            echo "  [統合検出] - 両方のログから検出された脅威 (より信頼性が高い)"
            ;;
    esac
    echo ""
    
    echo "レポート生成完了: $(date)"
    
    # Display summary based on log type
    case "$log_type" in
        "mixed_access_primary"|"mixed_error_primary")
            echo "総検出IP数: ${#suspicious_ips[@]}個 (access_log: ${access_log_threats}, error_log: ${error_log_threats}, 統合: ${integrated_threats})"
            ;;
        *)
            echo "総検出IP数: ${#suspicious_ips[@]}個 (${log_type_description}から検出)"
            ;;
    esac
    echo ""
}

# Function to generate formatted report with suspicious IPs, counts, reasons, and countries
# Sorts results by occurrence count in descending order
# Displays message when no suspicious activity is detected
# Includes timestamp of analysis execution
generate_report() {
    local analysis_timestamp="$1"
    local log_type="$2"
    
    # Use integrated report function for comprehensive analysis
    generate_integrated_report "$analysis_timestamp" "$log_type"
}

# Function to detect log type (access_log or error_log)
# Enhanced version that supports mixed log files and line-by-line detection
detect_log_type() {
    local log_file="$1"
    local sample_lines=20  # Increased sample size for better accuracy
    local access_log_count=0
    local error_log_count=0
    local ssl_request_log_count=0
    local ssl_access_log_count=0
    local mixed_log_detected=false
    
    echo "Analyzing log file format..." >&2
    
    # Read first few lines to determine log type
    while IFS= read -r line && [ $sample_lines -gt 0 ]; do
        sample_lines=$((sample_lines - 1))
        
        # Skip empty lines and comments
        [ -z "$line" ] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Check for Apache ssl_request_log patterns first (most specific)
        # Pattern: [timestamp] IP TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 "GET /path HTTP/1.1" 200
        if [[ "$line" =~ ^\[.*\][[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+TLS.*[[:space:]]+.*[[:space:]]+\".*\"[[:space:]]+[0-9]+ ]]; then
            ssl_request_log_count=$((ssl_request_log_count + 1))
        # Check for Nginx ssl_access_log patterns
        # Pattern: IP - - [timestamp] "GET /path HTTP/1.1" 200 size "referer" "user-agent" ssl_protocol ssl_cipher
        elif [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+-[[:space:]]+-[[:space:]]+\[.*\][[:space:]]+\".*\"[[:space:]]+[0-9]+[[:space:]]+[0-9-]+.*TLS ]]; then
            ssl_access_log_count=$((ssl_access_log_count + 1))
        # Check for access_log patterns (Common/Combined Log Format)
        # Pattern: IP - - [timestamp] "request" status size [optional fields]
        elif [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+-[[:space:]]+-[[:space:]]+\[.*\][[:space:]]+\".*\"[[:space:]]+[0-9]+[[:space:]]+[0-9-]+ ]]; then
            access_log_count=$((access_log_count + 1))
        # Check for Apache error_log patterns
        # Pattern: [timestamp] [level] [pid] [client IP:port] message
        elif [[ "$line" =~ ^\[.*\][[:space:]]+\[.*\][[:space:]]+\[.*\][[:space:]]+\[client[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+\] ]]; then
            error_log_count=$((error_log_count + 1))
        # Check for Nginx error_log patterns
        # Pattern: timestamp level: message, client: IP, server: hostname
        elif [[ "$line" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]+\[.*\].*client:[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*server: ]]; then
            error_log_count=$((error_log_count + 1))
        # Check for simplified error_log patterns
        # Pattern: [timestamp] [level] client IP message
        elif [[ "$line" =~ ^\[.*\][[:space:]]+\[.*\][[:space:]]+client[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            error_log_count=$((error_log_count + 1))
        # Check for generic error_log patterns (fallback)
        elif [[ "$line" =~ ^\[.*\].*\[.*\].*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            error_log_count=$((error_log_count + 1))
        fi
    done < "$log_file"
    
    # Calculate total counts
    local total_ssl_count=$((ssl_request_log_count + ssl_access_log_count))
    local total_access_count=$((access_log_count + total_ssl_count))
    local total_entries=$((total_access_count + error_log_count))
    
    # Check if we have mixed log types
    if [ $total_entries -gt 1 ]; then
        local non_zero_types=0
        [ $total_access_count -gt 0 ] && ((non_zero_types++))
        [ $error_log_count -gt 0 ] && ((non_zero_types++))
        
        if [ $non_zero_types -gt 1 ]; then
            mixed_log_detected=true
            echo "Mixed log format detected (access/ssl: $total_access_count, error_log: $error_log_count entries in sample)" >&2
        fi
    fi
    
    # Determine primary log type based on pattern matches (prioritize SSL logs)
    if [ $ssl_request_log_count -gt 0 ] && [ $ssl_request_log_count -ge $ssl_access_log_count ]; then
        if [ "$mixed_log_detected" = true ]; then
            echo "mixed_access_primary"  # Mixed logs still use line-by-line detection
        else
            echo "ssl_request_log"
        fi
    elif [ $ssl_access_log_count -gt 0 ]; then
        if [ "$mixed_log_detected" = true ]; then
            echo "mixed_access_primary"  # Mixed logs still use line-by-line detection
        else
            echo "ssl_access_log"
        fi
    elif [ $access_log_count -gt $error_log_count ]; then
        if [ "$mixed_log_detected" = true ]; then
            echo "mixed_access_primary"
        else
            echo "access_log"
        fi
    elif [ $error_log_count -gt 0 ]; then
        if [ "$mixed_log_detected" = true ]; then
            echo "mixed_error_primary"
        else
            echo "error_log"
        fi
    else
        echo "unknown"
    fi
}

# Function to detect log type for a single line (for mixed log files)
# This function is used when processing mixed log files line by line
detect_line_log_type() {
    local line="$1"
    
    # Skip empty lines and comments
    [ -z "$line" ] && return 1
    [[ "$line" =~ ^[[:space:]]*# ]] && return 1
    
    # Check for access_log patterns (Common/Combined Log Format)
    # Pattern: IP - - [timestamp] "request" status size [optional fields]
    if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+-[[:space:]]+-[[:space:]]+\[.*\][[:space:]]+\".*\"[[:space:]]+[0-9]+[[:space:]]+[0-9-]+ ]]; then
        echo "access_log"
        return 0
    # Check for Apache error_log patterns
    # Pattern: [timestamp] [level] [pid] [client IP:port] message
    elif [[ "$line" =~ ^\[.*\][[:space:]]+\[.*\][[:space:]]+\[.*\][[:space:]]+\[client[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+\] ]]; then
        echo "error_log"
        return 0
    # Check for Nginx error_log patterns
    # Pattern: timestamp level: message, client: IP, server: hostname
    elif [[ "$line" =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]+\[.*\].*client:[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*server: ]]; then
        echo "error_log"
        return 0
    # Check for simplified error_log patterns
    # Pattern: [timestamp] [level] client IP message
    elif [[ "$line" =~ ^\[.*\][[:space:]]+\[.*\][[:space:]]+client[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        echo "error_log"
        return 0
    # Check for generic error_log patterns (fallback)
    elif [[ "$line" =~ ^\[.*\].*\[.*\].*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        echo "error_log"
        return 0
    # Check for Apache ssl_request_log patterns
    # Pattern: [timestamp] IP TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 "GET /path HTTP/1.1" 200
    elif [[ "$line" =~ ^\[.*\][[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+TLS.*[[:space:]]+.*[[:space:]]+\".*\"[[:space:]]+[0-9]+ ]]; then
        echo "ssl_request_log"
        return 0
    # Check for Nginx ssl_access_log patterns
    # Pattern: IP - - [timestamp] "GET /path HTTP/1.1" 200 size "referer" "user-agent" ssl_protocol ssl_cipher
    elif [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+-[[:space:]]+-[[:space:]]+\[.*\][[:space:]]+\".*\"[[:space:]]+[0-9]+[[:space:]]+[0-9-]+.*TLS ]]; then
        echo "ssl_access_log"
        return 0
    else
        echo "unknown"
        return 1
    fi
}

# Function to parse error_log entry and extract components
parse_error_log_entry() {
    local log_line="$1"
    local line_number="${2:-unknown}"
    
    # Skip empty lines
    [ -z "$log_line" ] && return 1
    
    local timestamp=""
    local level=""
    local ip=""
    local message=""
    
    # Apache error_log format: [timestamp] [level] [pid] [client IP:port] message
    if [[ "$log_line" =~ ^\[([^\]]+)\].*\[([^\]]+)\].*\[client[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[0-9]+\][[:space:]]*(.*)$ ]]; then
        timestamp="${BASH_REMATCH[1]}"
        level="${BASH_REMATCH[2]}"
        ip="${BASH_REMATCH[3]}"
        message="${BASH_REMATCH[4]}"
    # Nginx error_log format: timestamp level: message, client: IP, server: hostname
    elif [[ "$log_line" =~ ^([0-9]{4}/[0-9]{2}/[0-9]{2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2})[[:space:]]+\[([^\]]+)\].*client:[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*$ ]]; then
        timestamp="${BASH_REMATCH[1]}"
        level="${BASH_REMATCH[2]}"
        ip="${BASH_REMATCH[3]}"
        message="$log_line"
    # Simplified error_log format: [timestamp] [level] client IP message
    elif [[ "$log_line" =~ ^\[([^\]]+)\].*\[([^\]]+)\].*client[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*(.*)$ ]]; then
        timestamp="${BASH_REMATCH[1]}"
        level="${BASH_REMATCH[2]}"
        ip="${BASH_REMATCH[3]}"
        message="${BASH_REMATCH[4]}"
    else
        # If no IP found in standard format, try to extract any IP from the line
        if [[ "$log_line" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
            ip="${BASH_REMATCH[1]}"
            message="$log_line"
            timestamp="unknown"
            level="unknown"
        else
            return 1
        fi
    fi
    
    # Export parsed components for use by calling function
    PARSED_IP="$ip"
    PARSED_TIMESTAMP="$timestamp"
    PARSED_LEVEL="$level"
    PARSED_MESSAGE="$message"
    
    return 0
}

# Function to parse ssl_request_log entry and extract components
# Supports both Apache ssl_request_log and Nginx ssl_access_log formats
parse_ssl_request_log_entry() {
    local log_line="$1"
    local line_number="${2:-unknown}"
    
    # Skip empty lines and comments
    if [ -z "$log_line" ] || [[ "$log_line" =~ ^[[:space:]]*# ]]; then
        return 1
    fi
    
    # Initialize variables to avoid contamination from previous calls
    LOG_IP=""
    LOG_TIMESTAMP=""
    LOG_REQUEST=""
    LOG_STATUS=""
    LOG_SIZE=""
    LOG_METHOD=""
    LOG_URL=""
    SSL_PROTOCOL=""
    SSL_CIPHER=""
    
    # Apache ssl_request_log format: [timestamp] IP TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 "GET /path HTTP/1.1" 200
    if [[ "$log_line" =~ ^\[([^\]]+)\][[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+\"([^\"]+)\"[[:space:]]+([0-9]+) ]]; then
        LOG_TIMESTAMP="${BASH_REMATCH[1]}"
        LOG_IP="${BASH_REMATCH[2]}"
        SSL_PROTOCOL="${BASH_REMATCH[3]}"
        SSL_CIPHER="${BASH_REMATCH[4]}"
        LOG_REQUEST="${BASH_REMATCH[5]}"
        LOG_STATUS="${BASH_REMATCH[6]}"
        LOG_SIZE="0"  # Not available in this format
        
        # Extract HTTP method and URL from request
        if [[ $LOG_REQUEST =~ ^([A-Z]+)[[:space:]]+([^[:space:]]+) ]]; then
            LOG_METHOD="${BASH_REMATCH[1]}"
            LOG_URL="${BASH_REMATCH[2]}"
        else
            LOG_METHOD="UNKNOWN"
            LOG_URL="$LOG_REQUEST"
        fi
        
    # Nginx ssl_access_log format: IP - - [timestamp] "GET /path HTTP/1.1" 200 size "referer" "user-agent" ssl_protocol ssl_cipher
    elif [[ "$log_line" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]+-[[:space:]]+-[[:space:]]+\[([^\]]+)\][[:space:]]+\"([^\"]+)\"[[:space:]]+([0-9]+)[[:space:]]+([0-9-]+).*[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)$ ]]; then
        LOG_IP="${BASH_REMATCH[1]}"
        LOG_TIMESTAMP="${BASH_REMATCH[2]}"
        LOG_REQUEST="${BASH_REMATCH[3]}"
        LOG_STATUS="${BASH_REMATCH[4]}"
        LOG_SIZE="${BASH_REMATCH[5]}"
        SSL_PROTOCOL="${BASH_REMATCH[6]}"
        SSL_CIPHER="${BASH_REMATCH[7]}"
        
        # Extract HTTP method and URL from request
        if [[ $LOG_REQUEST =~ ^([A-Z]+)[[:space:]]+([^[:space:]]+) ]]; then
            LOG_METHOD="${BASH_REMATCH[1]}"
            LOG_URL="${BASH_REMATCH[2]}"
        else
            LOG_METHOD="UNKNOWN"
            LOG_URL="$LOG_REQUEST"
        fi
        
    # Fallback: Try to parse as standard access_log with SSL info at the end
    elif [[ "$log_line" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]+-[[:space:]]+-[[:space:]]+\[([^\]]+)\][[:space:]]+\"([^\"]+)\"[[:space:]]+([0-9]+)[[:space:]]+([0-9-]+).*TLS ]]; then
        LOG_IP="${BASH_REMATCH[1]}"
        LOG_TIMESTAMP="${BASH_REMATCH[2]}"
        LOG_REQUEST="${BASH_REMATCH[3]}"
        LOG_STATUS="${BASH_REMATCH[4]}"
        LOG_SIZE="${BASH_REMATCH[5]}"
        SSL_PROTOCOL="TLS"  # Generic SSL/TLS indicator
        SSL_CIPHER="unknown"
        
        # Extract HTTP method and URL from request
        if [[ $LOG_REQUEST =~ ^([A-Z]+)[[:space:]]+([^[:space:]]+) ]]; then
            LOG_METHOD="${BASH_REMATCH[1]}"
            LOG_URL="${BASH_REMATCH[2]}"
        else
            LOG_METHOD="UNKNOWN"
            LOG_URL="$LOG_REQUEST"
        fi
        
    else
        # Invalid SSL request log format
        if (( line_number % 100 == 1 )); then
            echo "Warning: Invalid SSL request log format at line $line_number: ${log_line:0:80}..." >&2
        fi
        return 1
    fi
    
    # Basic validation
    if [[ ! $LOG_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        if (( line_number % 100 == 1 )); then
            echo "Warning: Invalid IP format in SSL request log at line $line_number: $LOG_IP" >&2
        fi
        return 1
    fi
    
    if [[ ! $LOG_STATUS =~ ^[0-9]{3}$ ]]; then
        if (( line_number % 100 == 1 )); then
            echo "Warning: Invalid status code in SSL request log at line $line_number: $LOG_STATUS" >&2
        fi
        return 1
    fi
    
    return 0
}

# Function to detect threats in error_log entries
detect_error_log_threats() {
    local ip="$1"
    local message="$2"
    
    # Define error_log threat patterns
    local -a ERROR_PATTERNS=(
        "ModSecurity.*denied"
        "ModSecurity.*blocked"
        "File does not exist"
        "Permission denied"
        "script not found"
        "script not found or unable to stat"
        "Invalid URI in request"
        "request failed: error reading the headers"
        "SSL handshake failed"
        "AH01630.*client denied"
        "access forbidden by rule"
        "client denied by server configuration"
        "Directory index forbidden"
        "Options ExecCGI is off"
        "Premature end of script headers"
        "malformed header from script"
    )
    
    local message_lower=$(echo "$message" | tr '[:upper:]' '[:lower:]')
    
    # Check for specific patterns first (more specific patterns have priority)
    local pattern_matched=false
    
    # Check for client denied patterns first (highest priority for access control violations)
    if [[ "$message_lower" =~ "client denied" ]] || [[ "$message_lower" =~ "ah01630.*client denied" ]]; then
        # IPごとのアクセス制御違反回数をカウント
        if [ -z "${ip_access_control_violations[$ip]}" ]; then
            ip_access_control_violations[$ip]=1
        else
            ((ip_access_control_violations[$ip]++))
        fi
        
        local violation_count=${ip_access_control_violations[$ip]}
        
        # 10回以上の場合のみレポートに記録
        if [ $violation_count -ge 10 ]; then
            record_suspicious_ip "$ip" "アクセス制御違反" "$violation_count"
            if [ "$DEBUG_MODE" = true ]; then
                echo "アクセス制御違反検出: IP $ip - ${violation_count}回目の違反を記録" >&2
            fi
        elif [ "$DEBUG_MODE" = true ]; then
            echo "アクセス制御違反カウント: IP $ip - ${violation_count}回 (閾値10回未満のため記録せず)" >&2
        fi
        pattern_matched=true
    # Check for ModSecurity patterns
    elif [[ "$message_lower" =~ "modsecurity.*denied" ]] || [[ "$message_lower" =~ "modsecurity.*blocked" ]]; then
        record_suspicious_ip "$ip" "WAF攻撃ブロック - ModSecurity" "1"
        pattern_matched=true
    # Check for file access patterns
    elif [[ "$message_lower" =~ "file does not exist" ]]; then
        record_suspicious_ip "$ip" "存在しないファイルへのアクセス - 偵察の可能性" "1"
        pattern_matched=true
    # Check for permission denied patterns
    elif [[ "$message_lower" =~ "permission denied" ]]; then
        record_suspicious_ip "$ip" "権限拒否 - 権限昇格攻撃の可能性" "1"
        pattern_matched=true
    # Check for script not found patterns
    elif [[ "$message_lower" =~ "script not found" ]]; then
        record_suspicious_ip "$ip" "不正なスクリプト実行試行" "1"
        pattern_matched=true
    # Check for invalid URI patterns
    elif [[ "$message_lower" =~ "invalid uri" ]]; then
        record_suspicious_ip "$ip" "不正なURI - 攻撃の可能性" "1"
        pattern_matched=true
    # Check for request failed patterns
    elif [[ "$message_lower" =~ "request failed.*error reading the headers" ]]; then
        record_suspicious_ip "$ip" "リクエスト失敗 - HTTP攻撃の可能性" "1"
        pattern_matched=true
    # Check for SSL handshake failed patterns
    elif [[ "$message_lower" =~ "ssl handshake failed" ]]; then
        record_suspicious_ip "$ip" "SSL/TLS攻撃の可能性" "1"
        pattern_matched=true
    # Check for other access forbidden patterns
    elif [[ "$message_lower" =~ "access forbidden by rule" ]]; then
        record_suspicious_ip "$ip" "アクセス制御違反" "1"
        pattern_matched=true
    # Check for directory index forbidden patterns
    elif [[ "$message_lower" =~ "directory index forbidden" ]]; then
        record_suspicious_ip "$ip" "error_log異常パターン検出" "1"
        pattern_matched=true
    # Check for other patterns
    elif [[ "$message_lower" =~ "options execcgi is off" ]] || [[ "$message_lower" =~ "premature end of script headers" ]] || [[ "$message_lower" =~ "malformed header from script" ]]; then
        record_suspicious_ip "$ip" "error_log異常パターン検出" "1"
        pattern_matched=true
    fi
    
    # If no specific pattern matched, record as general error_log anomaly
    if [ "$pattern_matched" = false ]; then
        record_suspicious_ip "$ip" "error_log異常パターン検出" "1"
    fi
}

# コマンドライン引数を解析する関数
parse_arguments() {
    LOG_FILE_RESULT=""
    
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
            --debug)
                DEBUG_MODE=true
                shift
                ;;
            --verbose)
                VERBOSE_OUTPUT=true
                shift
                ;;
            -h|--help)
                show_usage
                return 2  # Special return code for help
                ;;
            -*)
                display_error "INVALID_ARGUMENT" "不正なオプション: $1" 1
                ;;
            *)
                if [ -z "$LOG_FILE_RESULT" ]; then
                    LOG_FILE_RESULT="$1"
                    shift
                else
                    display_error "INVALID_ARGUMENT" "複数のログファイルが指定されました。1つのファイルのみ指定してください。" 1
                fi
                ;;
        esac
    done
    
    # ログファイルが指定されていない場合は使用方法を表示
    if [ -z "$LOG_FILE_RESULT" ]; then
        show_usage
        return 2  # Special return code for help
    fi
    
    return 0
}

# チャンク処理用の進捗表示関数
show_progress() {
    local current="$1"
    local total="$2"
    local chunk_num="$3"
    local progress=$((current * 100 / total))
    local bar_length=50
    local filled_length=$((progress * bar_length / 100))
    
    printf "\r進捗: チャンク %d [" "$chunk_num"
    printf "%*s" $filled_length | tr ' ' '='
    printf "%*s" $((bar_length - filled_length)) | tr ' ' '-'
    printf "] %d%% (%d/%d)" $progress $current $total
}

# 強化されたメモリクリーンアップ関数
cleanup_chunk_data() {
    ((performance_metrics["cleanup_count"]++))
    local cleanup_performed=false
    
    # 地理位置キャッシュのサイズ制限と最適化
    if [ ${#ip_country_cache[@]} -gt $MAX_CACHE_SIZE ]; then
        echo "メモリ最適化: 地理位置キャッシュをクリーンアップしています (${#ip_country_cache[@]} -> $MAX_CACHE_SIZE)..." >&2
        
        # LRU風の削除: 配列の前半を削除して後半を保持
        local temp_cache=()
        local keep_count=$((MAX_CACHE_SIZE * 3 / 4))  # 75%を保持
        local current_count=0
        
        for ip in "${!ip_country_cache[@]}"; do
            if [ $current_count -lt $keep_count ]; then
                temp_cache["$ip"]="${ip_country_cache[$ip]}"
                ((current_count++))
            fi
        done
        
        unset ip_country_cache
        declare -gA ip_country_cache
        for ip in "${!temp_cache[@]}"; do
            ip_country_cache["$ip"]="${temp_cache[$ip]}"
        done
        
        cleanup_performed=true
    fi
    
    # 疑わしいIPリストのサイズ制限
    if [ ${#suspicious_ips[@]} -gt $MAX_SUSPICIOUS_IPS ]; then
        echo "メモリ最適化: 疑わしいIPリストが上限に達しました (${#suspicious_ips[@]})。最新のエントリを保持します。" >&2
        ((performance_metrics["memory_warnings"]++))
        
        # 優先度の高い脅威を保持するための一時配列
        local temp_suspicious=()
        local high_priority_count=0
        
        # 高優先度の脅威を先に保持
        for ip in "${!suspicious_ips[@]}"; do
            local reason="${suspicious_ips[$ip]}"
            if [[ "$reason" =~ (SQLインジェクション|ディレクトリトラバーサル|高頻度アクセス) ]] && [ $high_priority_count -lt $((MAX_SUSPICIOUS_IPS / 2)) ]; then
                temp_suspicious["$ip"]="$reason"
                ((high_priority_count++))
            fi
        done
        
        # 残りの容量で他の脅威を保持
        local other_count=0
        local max_others=$((MAX_SUSPICIOUS_IPS - high_priority_count))
        
        for ip in "${!suspicious_ips[@]}"; do
            if [ -z "${temp_suspicious[$ip]}" ] && [ $other_count -lt $max_others ]; then
                temp_suspicious["$ip"]="${suspicious_ips[$ip]}"
                ((other_count++))
            fi
        done
        
        unset suspicious_ips
        declare -gA suspicious_ips
        for ip in "${!temp_suspicious[@]}"; do
            suspicious_ips["$ip"]="${temp_suspicious[$ip]}"
        done
        
        cleanup_performed=true
    fi
    
    # アクセス履歴データの最適化
    local total_ips=$((${#ip_access_history[@]} + ${#ip_404_counts[@]} + ${#ip_auth_failures[@]} + ${#ip_traversal_counts[@]}))
    if [ $total_ips -gt $MAX_TOTAL_IPS ]; then
        echo "メモリ最適化: IP追跡データをクリーンアップしています (総IP数: $total_ips)..." >&2
        
        # アクセス履歴の古いエントリを削除
        cleanup_access_history_data
        
        # 404カウントの低いエントリを削除
        cleanup_404_count_data
        
        # 認証失敗の古いエントリを削除
        cleanup_auth_failure_data
        
        # トラバーサル試行の低いエントリを削除
        cleanup_traversal_count_data
        
        # アクセス制御違反の低いエントリを削除
        cleanup_access_control_violation_data
        
        cleanup_performed=true
    fi
    
    # all_suspicious_detections配列のサイズ制限
    if [ ${#all_suspicious_detections[@]} -gt $((MAX_SUSPICIOUS_IPS * 2)) ]; then
        echo "メモリ最適化: 検出履歴をクリーンアップしています (${#all_suspicious_detections[@]} エントリ)..." >&2
        
        # 最新の検出のみを保持
        local keep_detections=$((MAX_SUSPICIOUS_IPS * 3 / 2))
        local temp_detections=("${all_suspicious_detections[@]:0:$keep_detections}")
        all_suspicious_detections=("${temp_detections[@]}")
        
        cleanup_performed=true
    fi
    
    if [ "$cleanup_performed" = true ]; then
        echo "メモリクリーンアップ完了。現在の使用状況:" >&2
        echo "  - 疑わしいIP: ${#suspicious_ips[@]}" >&2
        echo "  - 地理位置キャッシュ: ${#ip_country_cache[@]}" >&2
        echo "  - アクセス履歴: ${#ip_access_history[@]}" >&2
        echo "  - 検出履歴: ${#all_suspicious_detections[@]}" >&2
    fi
}

# アクセス履歴データのクリーンアップ
cleanup_access_history_data() {
    local current_time=$(date +%s)
    local cutoff_time=$((current_time - 1800))  # 30分前
    local cleaned_count=0
    
    # 古いアクセス履歴を削除
    for ip in "${!ip_access_history[@]}"; do
        local access_times=(${ip_access_history[$ip]})
        local recent_times=()
        
        for timestamp in "${access_times[@]}"; do
            if [ "$timestamp" -gt "$cutoff_time" ]; then
                recent_times+=("$timestamp")
            fi
        done
        
        if [ ${#recent_times[@]} -eq 0 ]; then
            unset ip_access_history["$ip"]
            unset ip_access_counts["$ip"]
            ((cleaned_count++))
        else
            ip_access_history["$ip"]="${recent_times[*]}"
            ip_access_counts["$ip"]=${#recent_times[@]}
        fi
    done
    
    echo "  - アクセス履歴: $cleaned_count 個の古いIPエントリを削除" >&2
}

# 404カウントデータのクリーンアップ
cleanup_404_count_data() {
    local cleaned_count=0
    
    # 404カウントが低いエントリを削除
    for ip in "${!ip_404_counts[@]}"; do
        if [ "${ip_404_counts[$ip]}" -lt 3 ]; then
            unset ip_404_counts["$ip"]
            ((cleaned_count++))
        fi
    done
    
    echo "  - 404カウント: $cleaned_count 個の低頻度IPエントリを削除" >&2
}

# 認証失敗データのクリーンアップ
cleanup_auth_failure_data() {
    local current_time=$(date +%s)
    local cutoff_time=$((current_time - 3600))  # 1時間前
    local cleaned_count=0
    
    # 古い認証失敗データを削除
    for ip in "${!ip_auth_failures[@]}"; do
        local failure_times=(${ip_auth_failures[$ip]})
        local recent_failures=()
        
        for timestamp in "${failure_times[@]}"; do
            if [ "$timestamp" -gt "$cutoff_time" ]; then
                recent_failures+=("$timestamp")
            fi
        done
        
        if [ ${#recent_failures[@]} -eq 0 ]; then
            unset ip_auth_failures["$ip"]
            ((cleaned_count++))
        else
            ip_auth_failures["$ip"]="${recent_failures[*]}"
        fi
    done
    
    echo "  - 認証失敗: $cleaned_count 個の古いIPエントリを削除" >&2
}

# トラバーサル試行データのクリーンアップ
cleanup_traversal_count_data() {
    local cleaned_count=0
    
    # トラバーサル試行が少ないエントリを削除
    for ip in "${!ip_traversal_counts[@]}"; do
        if [ "${ip_traversal_counts[$ip]}" -lt 2 ]; then
            unset ip_traversal_counts["$ip"]
            ((cleaned_count++))
        fi
    done
    
    echo "  - トラバーサル試行: $cleaned_count 個の低頻度IPエントリを削除" >&2
}

# アクセス制御違反データのクリーンアップ
cleanup_access_control_violation_data() {
    local cleaned_count=0
    
    # 違反回数が閾値未満のIPを削除（メモリ効率化）
    for ip in "${!ip_access_control_violations[@]}"; do
        if [ "${ip_access_control_violations[$ip]}" -lt 5 ]; then
            unset ip_access_control_violations["$ip"]
            ((cleaned_count++))
        fi
    done
    
    echo "  - アクセス制御違反: $cleaned_count 個の低頻度IPエントリを削除" >&2
}

# パフォーマンス測定とボトルネック解析（詳細モード時のみ実行）
analyze_performance_bottlenecks() {
    # 高速モード時はボトルネック分析をスキップ（すでに最適化済み）
    if [ "$DETAILED_MODE" != true ]; then
        return 0
    fi
    
    local end_time=$(date +%s)
    local total_time=$((end_time - performance_metrics["start_time"]))
    local processed_lines=${performance_metrics["processed_lines"]}
    local cleanup_count=${performance_metrics["cleanup_count"]}
    local memory_warnings=${performance_metrics["memory_warnings"]}
    
    echo "" >&2
    echo "=== パフォーマンス解析結果 ===" >&2
    echo "総処理時間: ${total_time}秒" >&2
    echo "処理行数: $processed_lines 行" >&2
    
    if [ $total_time -gt 0 ]; then
        local lines_per_second=$((processed_lines / total_time))
        echo "処理速度: $lines_per_second 行/秒" >&2
    fi
    
    echo "メモリクリーンアップ実行回数: $cleanup_count" >&2
    echo "メモリ警告回数: $memory_warnings" >&2
    
    # データ構造サイズの報告
    echo "" >&2
    echo "=== 最終メモリ使用状況 ===" >&2
    echo "疑わしいIP: ${#suspicious_ips[@]} / $MAX_SUSPICIOUS_IPS" >&2
    echo "地理位置キャッシュ: ${#ip_country_cache[@]} / $MAX_CACHE_SIZE" >&2
    echo "アクセス履歴: ${#ip_access_history[@]}" >&2
    echo "404カウント: ${#ip_404_counts[@]}" >&2
    echo "認証失敗: ${#ip_auth_failures[@]}" >&2
    echo "トラバーサル試行: ${#ip_traversal_counts[@]}" >&2
    echo "検出履歴: ${#all_suspicious_detections[@]}" >&2
    
    # ボトルネック分析
    echo "" >&2
    echo "=== ボトルネック分析 ===" >&2
    
    if [ $lines_per_second -lt 100 ]; then
        echo "⚠️  処理速度が低下しています。以下を検討してください:" >&2
        echo "   - ファイルサイズの分割" >&2
        echo "   - 高速モードの使用" >&2
        echo "   - 地理位置検索の無効化" >&2
    fi
    
    if [ $memory_warnings -gt 5 ]; then
        echo "⚠️  メモリ使用量が高いです。以下を検討してください:" >&2
        echo "   - チャンクサイズの削減" >&2
        echo "   - より頻繁なクリーンアップ" >&2
        echo "   - データ保持期間の短縮" >&2
    fi
    
    if [ $cleanup_count -gt 10 ]; then
        echo "ℹ️  メモリクリーンアップが頻繁に実行されました" >&2
        echo "   これは大容量ファイル処理では正常です" >&2
    fi
    
    echo "" >&2
}

# 大容量ログファイルのチャンク処理機能
process_log_chunks() {
    local log_file="$1"
    local chunk_size="${2:-1000}"  # デフォルト1000行
    
    # ファイルの総行数を取得
    echo "ファイルサイズを計算中..." >&2
    local total_lines=$(wc -l < "$log_file" 2>/dev/null || echo "0")
    
    if [ "$total_lines" -eq 0 ]; then
        echo "エラー: ファイルが空か、行数を取得できませんでした。" >&2
        return 1
    fi
    
    echo "チャンク処理開始: 総行数 $total_lines 行を $chunk_size 行ずつ処理します" >&2
    
    local current_line=0
    local chunk_num=1
    local chunk_lines=0
    
    # ログタイプを事前に検出
    local log_type=$(detect_log_type "$log_file")
    local is_mixed_log=false
    if [[ "$log_type" =~ ^mixed_ ]]; then
        is_mixed_log=true
    fi
    
    # チャンク処理のメインループ
    while IFS= read -r line || [ -n "$line" ]; do
        ((current_line++))
        ((chunk_lines++))
        ((performance_metrics["processed_lines"]++))
        
        # メモリ使用量監視
        check_memory_usage "$current_line"
        
        # データ構造最適化
        optimize_data_structures "$current_line"
        ((performance_metrics["processed_lines"]++))
        
        # 各行を処理（既存の処理ロジックを使用）
        process_single_line "$line" "$current_line" "$log_type" "$is_mixed_log"
        
        # チャンクサイズに達したら進捗表示とクリーンアップ
        if (( chunk_lines >= chunk_size )); then
            show_progress "$current_line" "$total_lines" "$chunk_num"
            cleanup_chunk_data
            chunk_lines=0
            ((chunk_num++))
        fi
        
        # 定期的なメモリクリーンアップ（CLEANUP_INTERVAL行ごと）
        if (( current_line % CLEANUP_INTERVAL == 0 )); then
            cleanup_chunk_data
        fi
        
        # 定期的な進捗更新（チャンク境界以外でも）
        if (( current_line % 500 == 0 )); then
            show_progress "$current_line" "$total_lines" "$chunk_num"
        fi
        
        # メモリ使用量の監視と早期警告
        if (( current_line % 10000 == 0 )); then
            monitor_memory_usage "$current_line" "$total_lines"
        fi
    done < "$log_file"
    
    # 最終進捗表示
    show_progress "$total_lines" "$total_lines" "$chunk_num"
    echo "" >&2
    echo "チャンク処理完了: $chunk_num チャンクを処理しました" >&2
    
    # 最終パフォーマンス解析（詳細モード時のみ）
    if [ "$DETAILED_MODE" = true ]; then
        analyze_performance_bottlenecks
    fi
}

# メモリ使用量の監視関数
monitor_memory_usage() {
    local current_line="$1"
    local total_lines="$2"
    
    # データ構造のサイズをチェック
    local total_data_structures=$((${#suspicious_ips[@]} + ${#ip_access_history[@]} + ${#ip_404_counts[@]} + ${#ip_auth_failures[@]} + ${#ip_traversal_counts[@]} + ${#ip_country_cache[@]}))
    
    # メモリ使用量が高い場合の警告
    if [ $total_data_structures -gt $((MAX_TOTAL_IPS * 4 / 5)) ]; then
        echo "⚠️  メモリ使用量警告: データ構造サイズ $total_data_structures (進捗: $((current_line * 100 / total_lines))%)" >&2
        ((performance_metrics["memory_warnings"]++))
        
        # 緊急クリーンアップの実行
        if [ $total_data_structures -gt $MAX_TOTAL_IPS ]; then
            echo "🚨 緊急メモリクリーンアップを実行中..." >&2
            cleanup_chunk_data
        fi
    fi
}

# 単一行の処理関数（チャンク処理から呼び出される）
process_single_line() {
    local line="$1"
    local line_number="$2"
    local log_type="$3"
    local is_mixed_log="$4"
    
    # For mixed logs, detect the type of each line
    local current_line_type="$log_type"
    if [ "$is_mixed_log" = true ]; then
        current_line_type=$(detect_line_log_type "$line")
        if [ "$current_line_type" = "unknown" ]; then
            ((error_count++))
            return
        fi
    fi
    
    # Process based on detected line type
    if [ "$current_line_type" = "access_log" ] || [[ "$current_line_type" =~ ^mixed_access ]]; then
        # Parse access_log entry
        if parse_log_entry "$line" "$line_number"; then
            ((processed_count++))
            
            # Convert timestamp to Unix time for time-based analysis
            local unix_time=$(timestamp_to_unix "$LOG_TIMESTAMP")
            
            # Skip entries with invalid timestamps
            if [ "$unix_time" -eq 0 ]; then
                ((error_count++))
                return
            fi
            
            # Detect patterns
            detect_high_frequency "$LOG_IP" "$unix_time"
            detect_4xx_errors "$LOG_IP" "$LOG_STATUS" "$unix_time"
            detect_sql_injection "$LOG_IP" "$LOG_REQUEST"
            detect_directory_traversal "$LOG_IP" "$LOG_REQUEST"
        else
            ((error_count++))
        fi
        
    elif [ "$current_line_type" = "ssl_request_log" ] || [ "$current_line_type" = "ssl_access_log" ]; then
        # Parse ssl_request_log entry
        if parse_ssl_request_log_entry "$line" "$line_number"; then
            ((processed_count++))
            
            # Convert timestamp to Unix time for time-based analysis
            local unix_time=$(timestamp_to_unix "$LOG_TIMESTAMP")
            
            # Skip entries with invalid timestamps
            if [ "$unix_time" -eq 0 ]; then
                ((error_count++))
                return
            fi
            
            # Detect patterns (same as access_log since SSL requests contain HTTP data)
            detect_high_frequency "$LOG_IP" "$unix_time"
            detect_4xx_errors "$LOG_IP" "$LOG_STATUS" "$unix_time"
            detect_sql_injection "$LOG_IP" "$LOG_REQUEST"
            detect_directory_traversal "$LOG_IP" "$LOG_REQUEST"
            
            # Additional SSL-specific logging (optional)
            if [ "$DETAILED_MODE" = true ]; then
                echo "SSL request processed: IP $LOG_IP, Protocol: $SSL_PROTOCOL, Cipher: $SSL_CIPHER, Request: ${LOG_REQUEST:0:50}..." >&2
            fi
        else
            ((error_count++))
        fi
        
    elif [ "$current_line_type" = "error_log" ] || [[ "$current_line_type" =~ ^mixed_error ]]; then
        # Parse error_log entry
        if parse_error_log_entry "$line" "$line_number"; then
            ((processed_count++))
            
            # Detect threats in error_log
            detect_error_log_threats "$PARSED_IP" "$PARSED_MESSAGE"
        else
            ((error_count++))
        fi
    fi
}

# メモリ使用量監視とクリーンアップ機能
check_memory_usage() {
    local current_line="$1"
    
    # 定期的なメモリチェック
    if (( current_line % MEMORY_CHECK_INTERVAL == 0 )); then
        # プロセスのメモリ使用量を取得（KB単位）
        local memory_kb=$(ps -o rss= -p $$ 2>/dev/null || echo "0")
        local memory_mb=$((memory_kb / 1024))
        
        if [ "$VERBOSE_OUTPUT" = true ]; then
            echo "メモリ使用量: ${memory_mb}MB (行数: $current_line)" >&2
        fi
        
        # メモリ使用量が閾値を超えた場合の警告
        if [ $memory_mb -gt 500 ]; then
            ((performance_metrics["memory_warnings"]++))
            echo "警告: メモリ使用量が高くなっています (${memory_mb}MB)" >&2
            
            # 積極的なクリーンアップを実行
            cleanup_memory_aggressive
        fi
    fi
}

# 積極的なメモリクリーンアップ機能
cleanup_memory_aggressive() {
    local cleaned_items=0
    
    # 古いアクセス履歴をクリーンアップ
    for ip in "${!ip_access_history[@]}"; do
        local access_count=$(echo "${ip_access_history[$ip]}" | wc -w)
        if [ $access_count -gt $MAX_ACCESS_HISTORY ]; then
            # 最新のエントリのみ保持
            local recent_entries=$(echo "${ip_access_history[$ip]}" | awk '{for(i=NF-'$((MAX_ACCESS_HISTORY/2))'+1; i<=NF; i++) printf "%s ", $i}')
            ip_access_history[$ip]="$recent_entries"
            ((cleaned_items++))
        fi
    done
    
    # 認証失敗履歴をクリーンアップ
    for ip in "${!ip_auth_failures[@]}"; do
        local failure_count=$(echo "${ip_auth_failures[$ip]}" | wc -w)
        if [ $failure_count -gt $MAX_AUTH_FAILURES ]; then
            # 最新のエントリのみ保持
            local recent_failures=$(echo "${ip_auth_failures[$ip]}" | awk '{for(i=NF-'$((MAX_AUTH_FAILURES/2))'+1; i<=NF; i++) printf "%s ", $i}')
            ip_auth_failures[$ip]="$recent_failures"
            ((cleaned_items++))
        fi
    done
    
    # 疑わしいIPリストのサイズ制限
    local suspicious_count=${#all_suspicious_detections[@]}
    if [ $suspicious_count -gt $MAX_SUSPICIOUS_IPS ]; then
        # 最新のエントリのみ保持（配列の後半を保持）
        local keep_count=$((MAX_SUSPICIOUS_IPS * 3 / 4))
        local start_index=$((suspicious_count - keep_count))
        
        local temp_array=()
        for ((i=start_index; i<suspicious_count; i++)); do
            temp_array+=("${all_suspicious_detections[i]}")
        done
        
        all_suspicious_detections=("${temp_array[@]}")
        ((cleaned_items++))
    fi
    
    # 全体のIP追跡数制限
    local total_ips=${#ip_access_times[@]}
    if [ $total_ips -gt $MAX_TOTAL_IPS ]; then
        # 古いIPエントリを削除（アクセス時間が古いものから）
        local temp_file=$(mktemp)
        for ip in "${!ip_access_times[@]}"; do
            echo "${ip_access_times[$ip]} $ip" >> "$temp_file"
        done
        
        # 時間順にソートして新しいものを保持
        local keep_count=$((MAX_TOTAL_IPS * 3 / 4))
        local ips_to_keep=$(sort -n "$temp_file" | tail -n $keep_count | awk '{print $2}')
        
        # 新しい配列を作成
        declare -A new_ip_access_times
        for ip in $ips_to_keep; do
            new_ip_access_times[$ip]="${ip_access_times[$ip]}"
        done
        
        # 古い配列を置き換え
        unset ip_access_times
        declare -A ip_access_times
        for ip in "${!new_ip_access_times[@]}"; do
            ip_access_times[$ip]="${new_ip_access_times[$ip]}"
        done
        
        rm -f "$temp_file"
        ((cleaned_items++))
    fi
    
    ((performance_metrics["cleanup_count"]++))
    
    if [ "$VERBOSE_OUTPUT" = true ] && [ $cleaned_items -gt 0 ]; then
        echo "メモリクリーンアップ完了: ${cleaned_items}項目を整理しました" >&2
    fi
}

# 効率的なデータ構造管理
optimize_data_structures() {
    local current_line="$1"
    
    # 定期的なデータ構造最適化
    if (( current_line % CLEANUP_INTERVAL == 0 )); then
        # 空のエントリを削除
        for ip in "${!ip_access_history[@]}"; do
            if [ -z "${ip_access_history[$ip]}" ]; then
                unset ip_access_history[$ip]
            fi
        done
        
        for ip in "${!ip_auth_failures[@]}"; do
            if [ -z "${ip_auth_failures[$ip]}" ]; then
                unset ip_auth_failures[$ip]
            fi
        done
        
        for ip in "${!ip_404_counts[@]}"; do
            if [ "${ip_404_counts[$ip]}" -eq 0 ]; then
                unset ip_404_counts[$ip]
            fi
        done
        
        # ガベージコレクション的な処理
        if [ "$PERFORMANCE_MODE" = true ]; then
            # 使用頻度の低いデータを削除
            cleanup_low_frequency_data
        fi
    fi
}

# 使用頻度の低いデータのクリーンアップ
cleanup_low_frequency_data() {
    # 404エラーが少ないIPを削除（閾値の半分以下）
    for ip in "${!ip_404_counts[@]}"; do
        if [ "${ip_404_counts[$ip]}" -lt 5 ]; then
            unset ip_404_counts[$ip]
        fi
    done
    
    # ディレクトリトラバーサル試行が少ないIPを削除
    for ip in "${!ip_traversal_counts[@]}"; do
        if [ "${ip_traversal_counts[$ip]}" -lt 3 ]; then
            unset ip_traversal_counts[$ip]
        fi
    done
    
    # アクセス制御違反が少ないIPを削除（閾値の半分以下）
    for ip in "${!ip_access_control_violations[@]}"; do
        if [ "${ip_access_control_violations[$ip]}" -lt 5 ]; then
            unset ip_access_control_violations[$ip]
        fi
    done
}

# パフォーマンス統計の表示
show_performance_stats() {
    if [ "$VERBOSE_OUTPUT" = true ] || [ "$DEBUG_MODE" = true ]; then
        local end_time=$(date +%s)
        local duration=$((end_time - performance_metrics["start_time"]))
        local lines_per_second=0
        
        if [ $duration -gt 0 ]; then
            lines_per_second=$((performance_metrics["processed_lines"] / duration))
        fi
        
        echo "" >&2
        echo "=== パフォーマンス統計 ===" >&2
        echo "処理時間: ${duration}秒" >&2
        echo "処理行数: ${performance_metrics["processed_lines"]}" >&2
        echo "スキップ行数: ${performance_metrics["skipped_lines"]}" >&2
        echo "検出数: ${performance_metrics["detection_count"]}" >&2
        echo "処理速度: ${lines_per_second}行/秒" >&2
        echo "クリーンアップ実行回数: ${performance_metrics["cleanup_count"]}" >&2
        echo "メモリ警告回数: ${performance_metrics["memory_warnings"]}" >&2
        
        if [ "${performance_metrics["cache_hits"]}" -gt 0 ] || [ "${performance_metrics["cache_misses"]}" -gt 0 ]; then
            local total_cache=$((performance_metrics["cache_hits"] + performance_metrics["cache_misses"]))
            local hit_rate=0
            if [ $total_cache -gt 0 ]; then
                hit_rate=$((performance_metrics["cache_hits"] * 100 / total_cache))
            fi
            echo "キャッシュヒット率: ${hit_rate}% (${performance_metrics["cache_hits"]}/${total_cache})" >&2
        fi
        
        echo "=========================" >&2
    fi
}

# Main processing function
main() {
    local log_file="$1"
    
    echo "Starting analysis of log file: $log_file"
    echo "Timestamp: $(date)"
    echo "----------------------------------------"
    
    # Detect log type
    local log_type=$(detect_log_type "$log_file")
    
    # Display appropriate message based on detected log type
    case "$log_type" in
        "access_log")
            echo "Detected log type: Apache/Nginx access_log (Common/Combined Log Format)"
            ;;
        "error_log")
            echo "Detected log type: Apache/Nginx error_log"
            ;;
        "ssl_request_log")
            echo "Detected log type: Apache ssl_request_log (SSL/TLS request log)"
            ;;
        "ssl_access_log")
            echo "Detected log type: Nginx ssl_access_log (SSL/TLS access log)"
            ;;
        "mixed_access_primary")
            echo "Detected log type: Mixed log file (primarily access_log with some error_log entries)"
            echo "Line-by-line detection will be used for accurate parsing."
            ;;
        "mixed_error_primary")
            echo "Detected log type: Mixed log file (primarily error_log with some access_log entries)"
            echo "Line-by-line detection will be used for accurate parsing."
            ;;
        "unknown")
            display_error "LOG_TYPE" "Unable to determine log file type. Please ensure the file contains valid Apache/Nginx access_log, error_log, or ssl_request_log entries."
            return 1
            ;;
        *)
            display_error "LOG_TYPE" "Unexpected log type detected: $log_type"
            return 1
            ;;
    esac
    
    # グローバル変数として宣言（チャンク処理で共有するため）
    line_count=0
    processed_count=0
    error_count=0
    local start_time=$(date +%s)
    
    # Trap to handle interruption gracefully
    trap 'echo ""; echo "Analysis interrupted by user. Generating partial report..."; generate_report "$(date) (INTERRUPTED)"; exit 130' INT TERM
    
    # Determine if we need line-by-line detection for mixed logs
    local is_mixed_log=false
    if [[ "$log_type" =~ ^mixed_ ]]; then
        is_mixed_log=true
        echo "Processing mixed log file with line-by-line detection..." >&2
    fi
    
    # ファイルサイズをチェックしてチャンク処理を決定
    local file_size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo "0")
    local chunk_threshold=$((50 * 1024 * 1024))  # 50MB
    
    if [ "$file_size" -gt "$chunk_threshold" ]; then
        echo "大容量ファイル検出 ($(($file_size / 1024 / 1024)) MB): チャンク処理を使用します" >&2
        # チャンク処理を実行
        process_log_chunks "$log_file" 1000
    else
        echo "標準処理を実行します" >&2
        # 従来の処理ループ（小さなファイル用）
        while IFS= read -r line || [ -n "$line" ]; do
            ((line_count++))
            ((performance_metrics["processed_lines"]++))
            
            # メモリ使用量監視
            check_memory_usage "$line_count"
            
            # データ構造最適化
            optimize_data_structures "$line_count"
            
            process_single_line "$line" "$line_count" "$log_type" "$is_mixed_log"
            
            # Display progress every 10000 lines for better performance
            if (( processed_count % 10000 == 0 )) && [ $processed_count -gt 0 ]; then
                echo "Processed $processed_count entries... (Line $line_count, Errors: $error_count)"
            fi
        done < "$log_file"
    fi
    
    # Calculate processing time
    local end_time=$(date +%s)
    local processing_time=$((end_time - start_time))
    
    echo "----------------------------------------"
    echo "Analysis complete."
    echo "Total lines read: $line_count"
    echo "Successfully parsed entries: $processed_count"
    echo "Invalid entries skipped: $error_count"
    echo "Processing time: ${processing_time} seconds"
    
    # Calculate performance metrics
    local success_rate=0
    local processing_rate=0
    if [ $line_count -gt 0 ]; then
        success_rate=$(( (processed_count * 100) / line_count ))
    fi
    if [ $processing_time -gt 0 ]; then
        processing_rate=$(( processed_count / processing_time ))
    fi
    
    echo "Success rate: ${success_rate}%"
    echo "Processing rate: ${processing_rate} entries/second"
    
    # Performance analysis and recommendations
    if [ $processing_rate -lt 100 ] && [ $processed_count -gt 1000 ]; then
        echo "PERFORMANCE: Processing rate is low. Consider:" >&2
        echo "  - Processing smaller file chunks" >&2
        echo "  - Disabling geolocation for faster analysis" >&2
    fi
    
    # Warn if success rate is low
    if [ $success_rate -lt 80 ] && [ $line_count -gt 10 ]; then
        echo "WARNING: Low success rate detected. Please verify log file format." >&2
        echo "Common issues: Mixed log formats, non-standard timestamps, encoding problems" >&2
    fi
    
    # Memory usage summary
    echo "Memory usage summary:"
    echo "  - Unique IPs tracked: ${#ip_access_history[@]} (high-frequency)"
    echo "  - Auth failure IPs: ${#ip_auth_failures[@]}"
    echo "  - 404 error IPs: ${#ip_404_counts[@]}"
    echo "  - Suspicious IPs detected: ${#suspicious_ips[@]}"
    echo "  - Geolocation cache entries: ${#ip_country_cache[@]}"
    
    # Generate integrated report with analysis timestamp
    local analysis_timestamp=$(date)
    echo "Generating integrated report..." >&2
    generate_report "$analysis_timestamp" "$log_type"
    
    # パフォーマンス統計の表示
    show_performance_stats
    
    # 最終パフォーマンス解析とボトルネック分析（詳細モード時のみ）
    if [ "$DETAILED_MODE" = true ]; then
        analyze_performance_bottlenecks
    fi
    
    # Clean up trap
    trap - INT TERM
}

# Script entry point
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    # Global error handler for unexpected errors
    error_handler() {
        local exit_code=$?
        local line_number=$1
        echo "ERROR: Unexpected error occurred at line $line_number (exit code: $exit_code)" >&2
        echo "Please check the log file format and try again." >&2
        exit $exit_code
    }
    
    # Performance-optimized dependency checking
    missing_commands=()
    
    # Check only essential commands for performance
    command -v date >/dev/null 2>&1 || missing_commands+=("date")
    command -v stat >/dev/null 2>&1 || missing_commands+=("stat")
    
    # Optional commands - warn but don't fail
    optional_warnings=()
    command -v curl >/dev/null 2>&1 || optional_warnings+=("curl (IP geolocation disabled)")
    
    # Display warnings for optional commands only if verbose mode
    if [ ${#optional_warnings[@]} -gt 0 ] && [ "${VERBOSE:-}" = "1" ]; then
        echo "INFO: Optional features disabled: ${optional_warnings[*]}" >&2
    fi
    
    # Check for missing required commands
    if [ ${#missing_commands[@]} -gt 0 ]; then
        display_error "MISSING_DEPENDENCIES" "Required commands not found: ${missing_commands[*]}" 1
    fi
    
    # Performance optimization: Set memory limits if available
    if command -v ulimit >/dev/null 2>&1; then
        # Increase file descriptor limit for better performance
        ulimit -n 4096 2>/dev/null || true
        # Set reasonable memory limit to prevent system overload
        ulimit -v 2097152 2>/dev/null || true  # 2GB virtual memory limit
    fi
    
    # Parse command line arguments
    parse_arguments "$@"
    parse_exit_code=$?
    
    # If parse_arguments exited with help code (2), exit normally
    if [ $parse_exit_code -eq 2 ]; then
        exit 0
    fi
    
    # If parse_arguments exited with error code, exit with error
    if [ $parse_exit_code -ne 0 ]; then
        exit $parse_exit_code
    fi
    
    # Use the global variable set by parse_arguments
    log_file="$LOG_FILE_RESULT"
    
    # Validate the log file
    validate_arguments "$log_file"
    
    # Run main analysis
    main "$log_file"
    main_exit_code=$?
    
    # Clean up and exit
    if [ $main_exit_code -ne 0 ]; then
        echo "Analysis completed with errors (exit code: $main_exit_code)" >&2
    fi
    
    exit $main_exit_code
fi