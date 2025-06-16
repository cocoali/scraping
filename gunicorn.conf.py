import os

# Railwayは$PORTを自動設定するので、それを使用
port = os.environ.get('PORT', '8000')
bind = f"0.0.0.0:{port}"

# ワーカー設定
workers = int(os.environ.get('WEB_CONCURRENCY', 1))  # Railwayの無料プランに合わせて削減
timeout = int(os.environ.get('TIMEOUT', 120))
worker_class = "sync"
keepalive = 5
max_requests = 1000
max_requests_jitter = 50

# ログ設定
loglevel = "info"  # debugからinfoに変更
accesslog = "-"
errorlog = "-"
capture_output = True
enable_stdio_inheritance = True

# デバッグ設定
reload = False
preload_app = True  # メモリ使用量を削減