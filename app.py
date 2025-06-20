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
        self.visited_urls = set()
        self.skipped_urls = set()
        self.total_pages = 0
        self.max_depth = 3
        self.max_pages = 90
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

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

    def _search_page(self, url, search_text, depth=0):
        """指定されたURLから検索テキストを探す"""
        if url in self.visited_urls or depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return {'results': []}

        self.visited_urls.add(url)
        self.total_pages += 1
        results = []

        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            # 認証エラーのチェック
            if response.status_code == 401:
                return {
                    'results': [{
                        'url': url,
                        'title': '認証エラー',
                        'depth': depth,
                        'error': '認証が必要です',
                        'requires_auth': True
                    }]
                }

            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else url

            # 本文の検索
            body_matches = []
            for text in soup.stripped_strings:
                if search_text.lower() in text.lower():
                    highlighted = self._highlight_text(text, search_text)
                    body_matches.append(highlighted)

            # headタグ内の検索
            head_matches = []
            for meta in soup.find_all('meta'):
                content = meta.get('content', '')
                if search_text.lower() in content.lower():
                    highlighted = self._highlight_text(content, search_text)
                    head_matches.append(highlighted)

            # リンクの検索
            href_matches = []
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    try:
                        absolute_url = urljoin(url, href)
                        if self._is_same_domain(absolute_url, url):
                            text = link.get_text(strip=True)
                            if search_text.lower() in text.lower():
                                href_matches.append({
                                    'text': self._highlight_text(text, search_text),
                                    'url': absolute_url
                                })
                    except:
                        continue

            if body_matches or head_matches or href_matches:
                results.append({
                    'url': url,
                    'title': title,
                    'depth': depth,
                    'body_matches': body_matches,
                    'head_matches': head_matches,
                    'href_matches': href_matches
                })

            # 再帰的にリンクを検索
            if depth < self.max_depth and len(self.visited_urls) < self.max_pages:
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href:
                        try:
                            absolute_url = urljoin(url, href)
                            if self._is_same_domain(absolute_url, url) and absolute_url not in self.visited_urls:
                                sub_results = self._search_page(absolute_url, search_text, depth + 1)
                                if sub_results and 'results' in sub_results:
                                    results.extend(sub_results['results'])
                        except:
                            continue

        except requests.exceptions.RequestException as e:
            results.append({
                'url': url,
                'title': 'エラー',
                'depth': depth,
                'error': str(e)
            })

        return {'results': results}

    def search(self, url, search_text, is_research=False, username=None, password=None):
        """指定されたURLから検索テキストを探す"""
        self.visited_urls.clear()
        self.skipped_urls.clear()
        self.total_pages = 0
        
        # 認証情報の設定
        if username and password:
            self.session.auth = (username, password)
        else:
            self.session.auth = None

        try:
            # 検索を実行
            results = self._search_page(url, search_text, 0)
            
            if not results or 'results' not in results:
                return {'error': '検索結果の取得に失敗しました'}

            # 検索結果を整形
            formatted_results = []
            for result in results['results']:
                if not isinstance(result, dict):
                    continue
                    
                # 認証エラーの処理
                if result.get('requires_auth'):
                    formatted_results.append({
                        'url': result.get('url', ''),
                        'title': result.get('title', ''),
                        'depth': result.get('depth', 0),
                        'error': result.get('error', ''),
                        'requires_auth': True
                    })
                    continue
                
                match_count = 0
                body_matches = result.get('body_matches', [])
                head_matches = result.get('head_matches', [])
                href_matches = result.get('href_matches', [])
                
                if body_matches:
                    match_count += len(body_matches)
                if head_matches:
                    match_count += len(head_matches)
                if href_matches:
                    match_count += len(href_matches)
                
                snippets = []
                if body_matches:
                    snippets.extend(body_matches)
                if head_matches:
                    snippets.extend(head_matches)
                
                href_snippets = []
                for h in href_matches:
                    try:
                        if isinstance(h, dict):
                            text = h.get('text', '')
                            url_val = h.get('original_url', h.get('href', ''))
                            href_snippets.append({'text': text, 'url': url_val})
                        elif isinstance(h, str):
                            href_snippets.append({'text': h, 'url': h})
                        else:
                            continue
                    except Exception as e:
                        logging.error(f"href_matchの処理中にエラー: {str(e)}")
                        continue
                
                formatted_results.append({
                    'url': result.get('url', ''),
                    'title': result.get('title', '') or result.get('url', ''),
                    'depth': result.get('depth', 0),
                    'matches': match_count,
                    'body_matches': body_matches,
                    'head_matches': head_matches,
                    'href_matches': href_snippets,
                    'snippets': snippets,
                    'error': result.get('error', '')
                })
            
            return formatted_results

        except Exception as e:
            logging.error(f"検索処理中にエラー: {str(e)}")
            import traceback
            traceback.print_exc()
            return {'error': str(e)}

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
            'is_research': is_research
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
