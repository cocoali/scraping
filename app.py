# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import base64
import os
import json
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import redis
from limits.storage import RedisStorage, MemoryStorage
from dotenv import load_dotenv
import sys
import logging

# ロギングの設定
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# 環境変数の読み込み
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# デバッグモードの設定
app.debug = os.environ.get('FLASK_ENV') == 'development'

# Redisの設定
# Redisの設定（Railway Redis使用時）
redis_url = os.environ.get('REDIS_URL') or os.environ.get('REDIS_PRIVATE_URL')

if redis_url:
    try:
        # Railwayの場合、SSL設定が必要な場合がある
        if redis_url.startswith('rediss://'):
            redis_client = redis.from_url(redis_url, ssl_cert_reqs=None)
        else:
            redis_client = redis.from_url(redis_url)
        
        redis_client.ping()
        storage_backend = RedisStorage(redis_url)
        logging.info("Successfully connected to Redis")
    except Exception as e:
        logging.warning(f"Redis connection failed: {str(e)}")
        storage_backend = MemoryStorage()
else:
    storage_backend = MemoryStorage()

# レート制限の設定
try:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri=redis_url if redis_url else "memory://",
        default_limits=["200 per day", "50 per hour"]
    )
    logging.info("Rate limiter initialized successfully")
except Exception as e:
    logging.error(f"Failed to initialize rate limiter: {str(e)}")
    raise

# タイムアウトを設定
app.config['TIMEOUT'] = int(os.environ.get('TIMEOUT', 500))

# ユーザー認証用のデコレータ
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ユーザー情報（本番環境ではデータベースを使用することを推奨）
USERS = {
    'admin': 'b65fe679c5abc007b55e3dfd28b782d5b9b2cc75fa739ccda4e751fa35e7a905378e05edf99169596f73864d545fdcf5f638f9d9e847bc8c2e3d6626318d0e31'  # 'password123'のSHA512ハッシュ値
}

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # パスワードのSHA512ハッシュを計算
        password_hash = hashlib.sha512(password.encode()).hexdigest()
        
        if username in USERS and USERS[username] == password_hash:
            session['user'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='ユーザー名またはパスワードが正しくありません。')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=session['user'])

@app.route('/history')
@login_required
def history():
    """検索履歴ページを表示"""
    try:
        with open('search_history.json', 'r', encoding='utf-8') as f:
            history = json.load(f)
    except FileNotFoundError:
        history = []
    
    # 履歴を日時でソート（新しい順）
    history.sort(key=lambda x: x.get('last_updated', ''), reverse=True)
    
    return render_template('history.html', history=history)

class WebTextSearcher:
    def __init__(self):
        self.timeout = 10
        self.visited_urls = set()
        self.max_depth = 3
        self.max_pages = 90
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.history_file = 'search_history.json'
        self.search_history = {}
        self.load_history()

    def load_history(self):
        """検索履歴を読み込む"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    try:
                        history_data = json.load(f)
                        if isinstance(history_data, dict):
                            self.search_history = history_data
                        elif isinstance(history_data, list):
                            # リスト形式の場合は辞書形式に変換
                            self.search_history = {}
                            for entry in history_data:
                                if isinstance(entry, dict) and 'search_text' in entry:
                                    self.search_history[entry['search_text']] = {
                                        'urls': entry.get('urls', []),
                                        'results': entry.get('results', []),
                                        'last_updated': entry.get('last_updated', datetime.now().isoformat())
                                    }
                        else:
                            self.search_history = {}
                    except json.JSONDecodeError:
                        logging.error("検索履歴のJSONデコードに失敗しました")
                        self.search_history = {}
            else:
                self.search_history = {}
                self.save_history()
        except Exception as e:
            logging.error(f"検索履歴の読み込み中にエラー: {str(e)}")
            self.search_history = {}

    def save_history(self):
        """検索履歴を保存"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.search_history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logging.error(f"検索履歴の保存中にエラー: {str(e)}")

    def _highlight_text(self, text, search_text):
        """検索テキストをハイライト表示"""
        pattern = re.compile(re.escape(search_text), re.IGNORECASE)
        return pattern.sub(lambda m: f'<mark>{m.group()}</mark>', text)

    def _is_same_domain(self, url, base_url):
        """同じドメインかチェック"""
        try:
            return urlparse(url).netloc == urlparse(base_url).netloc
        except:
            return False

    def search(self, url, search_text, auth=None, skip_visited=True):
        """指定されたURLから検索を開始"""
        logging.info(f"検索開始: URL={url}, 検索テキスト={search_text}")
        self.visited_urls = set()
        results = []
        error_occurred = False
        error_message = None
        
        # 認証情報の検証
        if auth and isinstance(auth, dict):
            if not auth.get('username') or not auth.get('password'):
                error_occurred = True
                error_message = "認証情報が不完全です。ユーザー名とパスワードを入力してください。"
                return {
                    'success': False,
                    'results': results,
                    'total_pages': 0,
                    'error': error_message,
                    'requires_auth': True
                }
        
        # 検索履歴から既に検索済みのURLを取得
        if skip_visited and search_text in self.search_history:
            try:
                history_entry = self.search_history[search_text]
                if isinstance(history_entry, dict) and 'urls' in history_entry:
                    self.visited_urls.update(history_entry['urls'])
                    logging.info(f"既に検索済みのURL数: {len(self.visited_urls)}")
            except Exception as e:
                logging.error(f"検索履歴の処理中にエラー: {str(e)}")
        
        try:
            self._search_page(url, search_text, depth=0, results=results, auth=auth)
            
            # 検索履歴を更新
            if search_text not in self.search_history:
                self.search_history[search_text] = {
                    'urls': [],
                    'results': [],
                    'last_updated': datetime.now().isoformat()
                }
            
            # 新しい結果を追加
            self.search_history[search_text]['urls'].extend(list(self.visited_urls))
            self.search_history[search_text]['results'].extend(results)
            self.search_history[search_text]['last_updated'] = datetime.now().isoformat()
            
            # 重複を除去
            self.search_history[search_text]['urls'] = list(set(self.search_history[search_text]['urls']))
            
            self.save_history()
            
        except Exception as e:
            error_occurred = True
            error_message = str(e)
            logging.error(f"検索中にエラー: {error_message}")
        
        # 結果を返す（エラーが発生していても、取得済みのデータを返す）
        return {
            'success': not error_occurred,
            'results': results,
            'total_pages': len(self.visited_urls),
            'error': error_message if error_occurred else None,
            'partial_results': error_occurred and len(results) > 0,
            'requires_auth': error_occurred and '認証' in error_message
        }

    def _search_page(self, url, search_text, depth=0, results=None, auth=None):
        """指定されたURLのページを検索"""
        if results is None:
            results = []
        
        if url in self.visited_urls or depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return
        
        self.visited_urls.add(url)
        logging.info(f"ページ検索中: {url} (深さ: {depth}, 訪問済みURL数: {len(self.visited_urls)})")
        
        try:
            # 認証情報の設定
            if auth and isinstance(auth, dict) and 'username' in auth and 'password' in auth:
                auth_tuple = (auth['username'], auth['password'])
                self.session.auth = auth_tuple
                logging.info(f"認証情報を設定: {auth['username']}")
            else:
                self.session.auth = None
            
            response = self.session.get(url, timeout=self.timeout)
            
            # 認証エラーの処理
            if response.status_code == 401:
                logging.error(f"認証エラー: {url}")
                results.append({
                    'url': url,
                    'title': '認証エラー',
                    'depth': depth,
                    'error': '認証に失敗しました。ユーザー名とパスワードを確認してください。',
                    'requires_auth': True
                })
                return
            
            response.raise_for_status()
            
            # エンコーディングを適切に設定
            if response.encoding == 'ISO-8859-1':
                response.encoding = response.apparent_encoding
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # タイトルの取得
            title = soup.find('title')
            title = title.get_text() if title else "タイトルなし"
            
            # 本文の検索
            body_matches = []
            for text in soup.stripped_strings:
                if search_text in text:
                    body_matches.append(text)
            
            # headタグ内の検索
            head_matches = []
            for meta in soup.find_all('meta'):
                content = meta.get('content', '')
                if search_text in content:
                    head_matches.append(content)
            
            # href属性の検索
            href_matches = []
            for link in soup.find_all('a', href=True):
                if search_text in link.get_text():
                    href_matches.append({
                        'text': link.get_text(),
                        'url': link['href'],
                        'original_url': urljoin(url, link['href'])
                    })
            
            # 結果の追加
            if body_matches or head_matches or href_matches:
                results.append({
                    'url': url,
                    'title': title,
                    'depth': depth,
                    'body_matches': body_matches,
                    'head_matches': head_matches,
                    'href_matches': href_matches
                })
            
            # リンク先の検索（max_pagesの制限を考慮）
            if len(self.visited_urls) < self.max_pages:
                for link in soup.find_all('a', href=True):
                    if len(self.visited_urls) >= self.max_pages:
                        break
                    link_url = urljoin(url, link['href'])
                    if link_url.startswith(('http://', 'https://')):
                        self._search_page(link_url, search_text, depth + 1, results, auth)
                    
        except requests.exceptions.RequestException as e:
            logging.error(f"リクエストエラー: {url} - {str(e)}")
            results.append({
                'url': url,
                'title': 'エラー',
                'depth': depth,
                'error': str(e)
            })
        except Exception as e:
            logging.error(f"予期せぬエラー: {url} - {str(e)}")
            results.append({
                'url': url,
                'title': 'エラー',
                'depth': depth,
                'error': str(e)
            })

@app.route('/check_auth', methods=['POST'])
def check_auth():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URLが指定されていません'}), 400
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 401:
            return jsonify({'requires_auth': True})
        return jsonify({'requires_auth': False})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'認証チェックエラー: {str(e)}'}), 500

@app.route('/search', methods=['POST'])
def search():
    url = request.form.get('url')
    search_text = request.form.get('search_text')
    is_research = request.form.get('is_research') == 'true'
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not url or not search_text:
        return jsonify({'error': 'URLと検索テキストは必須です'}), 400
    
    try:
        searcher = WebTextSearcher()
        results = searcher.search(url, search_text, is_research, username, password)
        
        if isinstance(results, dict) and results.get('error'):
            if results.get('requires_auth'):
                return jsonify({
                    'error': results['error'],
                    'requires_auth': True
                }), 401
            return jsonify({'error': results['error']}), 500
        
        return jsonify({
            'results': results,
            'total_pages': searcher.total_pages,
            'is_research': is_research,
            'skipped_count': len(searcher.skipped_urls)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/search_history', methods=['GET'], endpoint='search_history_get')
@login_required
def get_search_history():
    """検索履歴を取得"""
    try:
        if os.path.exists('search_history.json'):
            with open('search_history.json', 'r', encoding='utf-8') as f:
                history = json.load(f)
            return jsonify({
                'success': True,
                'history': history
            })
        return jsonify({
            'success': True,
            'history': []
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'success': False,
        'error': 'リクエストが多すぎます。しばらく待ってから再試行してください。'
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal Server Error: {str(error)}")
    return jsonify({'error': 'Internal Server Error', 'details': str(error)}), 500

@app.route('/health')
def health_check():
    try:
        # Redis接続確認
        redis_connected = False
        if storage_backend and hasattr(storage_backend, 'storage'):
            try:
                if hasattr(storage_backend.storage, 'ping'):
                    storage_backend.storage.ping()
                    redis_connected = True
            except:
                pass
        
        # 基本的なヘルスチェック情報
        health_info = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'redis_connected': redis_connected,
            'storage_backend': type(storage_backend).__name__ if storage_backend else 'None'
        }
        
        return jsonify(health_info), 200
    except Exception as e:
        logging.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('RAILWAY_ENVIRONMENT') != 'production'  # Railway用
    app.run(host='0.0.0.0', port=port, debug=debug)
