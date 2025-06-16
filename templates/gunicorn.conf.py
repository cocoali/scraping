import os

# バインドアドレス
bind = f"0.0.0.0:{os.environ.get('PORT', 8080)}"

# ワーカー設定
workers = 1
worker_class = "gthread"
threads = 2
worker_connections = 1000

# タイムアウト設定
timeout = 300  # 5分
keepalive = 5
max_requests = 1000
max_requests_jitter = 100

# ログ設定
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# プロセス名
proc_name = "text-searcher"

# 再起動設定
preload_app = True
reload = False

# メモリ使用量制限
worker_tmp_dir = "/dev/shm"
