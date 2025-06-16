import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict

class WebTextSearcher:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.visited_urls = set()
        self.results = []
        self.progress_callback = None
        self.max_depth = 4
        self.max_urls = 100
        self.timeout = 20
        self.batch_size = 10
        self.common_content = set()  # 共通コンテンツを保存するセット
        self.common_content_threshold = 0.7  # 共通コンテンツと判定する閾値
        
    def search(self, base_url, search_text, progress_callback=None):
        """メインの検索関数"""
        self.visited_urls.clear()
        self.results.clear()
        self.progress_callback = progress_callback
        
        try:
            # バッチ処理でクロール
            urls_to_crawl = [base_url]
            current_depth = 0
            
            while urls_to_crawl and current_depth <= self.max_depth:
                batch = urls_to_crawl[:self.batch_size]
                urls_to_crawl = urls_to_crawl[self.batch_size:]
                
                for url in batch:
                    if len(self.visited_urls) >= self.max_urls:
                        break
                    self._crawl_and_search(url, search_text, current_depth, base_url)
                
                current_depth += 1
                time.sleep(1)  # バッチ間の待機時間
            
            return {
                'success': True,
                'results': self.results,
                'total_pages': len(self.visited_urls)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'results': self.results,
                'total_pages': len(self.visited_urls)
            }
    
    def _crawl_and_search(self, url, search_text, depth, base_domain):
        """再帰的にページをクロールして検索"""
        if (url in self.visited_urls or
            not self._is_same_domain(url, base_domain)):
            return
        
        self.visited_urls.add(url)
        
        if self.progress_callback:
            self.progress_callback(f"クロール中: {url}")
        
        try:
            # ページを取得
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # エンコーディングを適切に設定
            if response.encoding == 'ISO-8859-1':
                response.encoding = response.apparent_encoding
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # ヘッダー、フッター、サイドバーなどの共通コンテンツを除去
            for tag in soup.find_all(['header', 'footer', 'nav', 'aside']):
                tag.decompose()
            
            # JavaScriptやCSSを除去
            for script in soup(["script", "style"]):
                script.decompose()
            
            # メインコンテンツを抽出
            main_content = self._extract_main_content(soup)
            if not main_content:
                return
                
            # テキストを抽出
            text_content = main_content.get_text()
            clean_text = re.sub(r'\s+', ' ', text_content).strip()
            
            # 共通コンテンツかどうかをチェック
            if self._is_common_content(clean_text):
                return
                
            # 新しい共通コンテンツとして保存
            self.common_content.add(clean_text)
            
            # 検索テキストをチェック
            matches = self._find_matches(clean_text, search_text)
            
            if matches:
                # ページタイトルを取得
                title = soup.find('title')
                page_title = title.get_text() if title else "タイトルなし"
                
                # マッチした文脈を抽出
                context_snippets = self._extract_context(clean_text, search_text)
                
                self.results.append({
                    'url': url,
                    'title': page_title.strip(),
                    'matches': int(len(matches)) if matches is not None else 0,
                    'snippets': context_snippets[:3]
                })
            
            # 次の階層のリンクを取得
            if depth < self.max_depth:
                links = self._extract_links(soup, url)
                for link in links[:15]:
                    if len(self.visited_urls) < self.max_urls:
                        time.sleep(0.1)
                        self._crawl_and_search(link, search_text, depth + 1, base_domain)
        
        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")
    
    def _is_same_domain(self, url, base_url):
        """同じドメインかチェック"""
        try:
            return urlparse(url).netloc == urlparse(base_url).netloc
        except:
            return False
    
    def _find_matches(self, text, search_text):
        """テキスト内の一致を検索"""
        pattern = re.compile(re.escape(search_text), re.IGNORECASE)
        return pattern.findall(text)
    
    def _extract_context(self, text, search_text, context_length=100):
        """マッチした箇所の前後の文脈を抽出"""
        pattern = re.compile(f'(.{{0,{context_length}}})({re.escape(search_text)})(.{{0,{context_length}}})', re.IGNORECASE)
        matches = pattern.findall(text)
        
        snippets = []
        for before, match, after in matches[:5]:  # 最大5個のマッチ
            snippet = f"...{before.strip()}<mark>{match}</mark>{after.strip()}..."
            snippets.append(snippet)
        
        return snippets
    
    def _extract_links(self, soup, base_url):
        """ページからリンクを抽出"""
        links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            
            # 有効なHTTP/HTTPSリンクのみ
            if full_url.startswith(('http://', 'https://')):
                links.append(full_url)
        
        return list(set(links))  # 重複を除去
    
    def _is_common_content(self, text):
        """テキストが共通コンテンツかどうかを判定"""
        if not text.strip():
            return True
            
        # 既存の共通コンテンツと比較
        for common in self.common_content:
            if self._calculate_similarity(text, common) > self.common_content_threshold:
                return True
        return False
        
    def _calculate_similarity(self, text1, text2):
        """2つのテキストの類似度を計算（簡易版）"""
        # テキストを単語に分割
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        # 共通の単語数を計算
        common_words = words1.intersection(words2)
        
        # 類似度を計算（Jaccard係数）
        if not words1 or not words2:
            return 0
        return len(common_words) / len(words1.union(words2))
        
    def _extract_main_content(self, soup):
        """メインコンテンツを抽出"""
        # 一般的なメインコンテンツのセレクタ
        main_selectors = [
            'main', 'article', '.main-content', '#main-content',
            '.content', '#content', '.post', '.article'
        ]
        
        # メインコンテンツを探す
        for selector in main_selectors:
            main_content = soup.select_one(selector)
            if main_content:
                return main_content
                
        # メインコンテンツが見つからない場合はbody全体を使用
        return soup.body