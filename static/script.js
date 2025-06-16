document.addEventListener('DOMContentLoaded', function () {
    const searchForm = document.getElementById('searchForm');
    const statusDiv = document.getElementById('status');
    const resultsDiv = document.getElementById('results');
    const searchBtn = document.getElementById('searchBtn');
    const spinner = document.getElementById('loadingSpinner');
    const loadingDiv = document.getElementById('loading');
    const searchHistoryDiv = document.getElementById('searchHistory');
    let currentSearchText = '';
    let currentUrl = '';

    // マッチ詳細の表示/非表示を切り替える関数
    window.toggleMatches = function(element) {
        const details = element.nextElementSibling;
        const isHidden = details.style.display === 'none';
        details.style.display = isHidden ? 'block' : 'none';
        element.textContent = `マッチ数: ${element.textContent.split(':')[1].trim().split(' ')[0]} ${isHidden ? '▲' : '▼'}`;
    };

    // 検索履歴を読み込む
    loadSearchHistory();

    searchForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        
        const url = document.getElementById('url').value;
        const searchText = document.getElementById('search_text').value;
        const isResearch = searchBtn.textContent.includes('再検索');
        
        // ローディング表示
        searchBtn.disabled = true;
        searchBtn.textContent = '検索中...';
        resultsDiv.innerHTML = '<div class="loading">検索中...</div>';
        
        try {
            const response = await fetch('/search', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    url: url,
                    search_text: searchText,
                    is_research: isResearch
                })
            });
            
            const data = await response.json();
            
            if (data.error) {
                resultsDiv.innerHTML = `<div class="error">${data.error}</div>`;
            } else {
                // 検索結果を表示
                let html = '';
                
                if (data.is_research && data.skipped_count > 0) {
                    html += `<div class="info">前回の検索でスキップされた${data.skipped_count}件のURLを検索しました。</div>`;
                }
                
                if (data.results.length === 0) {
                    html += '<div class="no-results">検索結果が見つかりませんでした。</div>';
                } else {
                    // 階層ごとに結果をグループ化
                    const resultsByDepth = {};
                    data.results.forEach(result => {
                        const depth = result.depth || 0;
                        if (!resultsByDepth[depth]) {
                            resultsByDepth[depth] = [];
                        }
                        resultsByDepth[depth].push(result);
                    });

                    // 階層ごとに結果を表示
                    Object.keys(resultsByDepth).sort((a, b) => Number(a) - Number(b)).forEach(depth => {
                        const results = resultsByDepth[depth];
                        html += `<div class="depth-section">
                            <h3>階層 ${depth}</h3>
                            <div class="results-grid">`;
                        
                        results.forEach(result => {
                            html += `
                                <div class="result-item">
                                    <h4><a href="${result.url}" target="_blank">${result.title}</a></h4>
                                    <p class="url">${result.url}</p>
                                    <div class="matches-section">
                                        <p class="matches">マッチ数: ${result.matches}</p>
                                        <div class="matches-details">
                                            ${result.body_matches.length > 0 ? `
                                                <div class="match-section">
                                                    <h5>本文の一致</h5>
                                                    ${result.body_matches.map(match => `<div class="match">${match}</div>`).join('')}
                                                </div>
                                            ` : ''}
                                            ${result.head_matches.length > 0 ? `
                                                <div class="match-section">
                                                    <h5>ヘッダーの一致</h5>
                                                    ${result.head_matches.map(match => `<div class="match">${match}</div>`).join('')}
                                                </div>
                                            ` : ''}
                                            ${result.href_matches.length > 0 ? `
                                                <div class="match-section">
                                                    <h5>リンクの一致</h5>
                                                    ${result.href_matches.map(match => `
                                                        <div class="match">
                                                            <a href="${match.url}" target="_blank">${match.text}</a>
                                                        </div>
                                                    `).join('')}
                                                </div>
                                            ` : ''}
                                        </div>
                                    </div>
                                </div>
                            `;
                        });
                        
                        html += `</div></div>`;
                    });
                }
                
                // 検索統計情報を表示
                html += `
                    <div class="search-stats">
                        <p>検索対象URL数: ${data.total_pages}件</p>
                        <p>検索結果数: ${data.results.length}件</p>
                    </div>
                `;
                
                resultsDiv.innerHTML = html;
                
                // 検索ボタンのテキストを更新
                if (data.is_research) {
                    searchBtn.textContent = '🔍 未検索ページを検索';
                } else {
                    searchBtn.textContent = '🔍 検索';
                }
            }
        } catch (error) {
            resultsDiv.innerHTML = `<div class="error">エラーが発生しました: ${error.message}</div>`;
        } finally {
            searchBtn.disabled = false;
        }
    });

    function resetUI() {
        resultsDiv.innerHTML = '';
        statusDiv.style.display = 'none';
    }

    function showLoading() {
        searchBtn.disabled = true;
        searchBtn.textContent = '🔍 検索中...';
        spinner.style.display = 'block';
        loadingDiv.style.display = 'block';
        showStatus('検索を開始しています...', 'loading');
    }

    function hideLoading() {
        searchBtn.disabled = false;
        searchBtn.textContent = '🔍 検索開始';
        spinner.style.display = 'none';
        loadingDiv.style.display = 'none';
    }

    function showStatus(message, type) {
        statusDiv.className = `status ${type}`;
        statusDiv.textContent = message;
        statusDiv.style.display = 'block';
    }

    function showNoResults() {
        resultsDiv.innerHTML = `
          <div class="no-results">
              <h3>🔍 検索結果なし</h3>
              <p>該当するテキストが見つかりませんでした</p>
              <p>別のキーワードで検索してみてください</p>
          </div>
      `;
    }

    function displayResults(results) {
        console.log('検索結果の表示:', results);

        if (!results || results.length === 0) {
            resultsDiv.innerHTML = '<div class="no-results">検索結果が見つかりませんでした</div>';
            return;
        }

        const resultsHtml = results.map(result => {
            const sections = [];

            // 本文のマッチ
            if (result.body_matches && result.body_matches.length > 0) {
                sections.push(`
                    <div class="result-section">
                        <h3>本文の一致</h3>
                        <div class="matches">
                            ${result.body_matches.map(match => `<div class="match">${match}</div>`).join('')}
                        </div>
                    </div>
                `);
            }

            // headタグのマッチ
            if (result.head_matches && result.head_matches.length > 0) {
                sections.push(`
                    <div class="result-section">
                        <h3>headタグ内の一致</h3>
                        <div class="matches">
                            ${result.head_matches.map(match => `<div class="match">${match}</div>`).join('')}
                        </div>
                    </div>
                `);
            }

            // href属性のマッチ
            if (result.href_matches && Array.isArray(result.href_matches) && result.href_matches.length > 0) {
                sections.push(`
                    <div class="result-section">
                        <h3>リンクの一致</h3>
                        <div class="matches">
                            ${result.href_matches.map(match => {
                                if (!match) return '';
                                const text = match.text || match.url || '';
                                const url = match.url || match.original_url || '';
                                return `<div class="match">
                                    <a href="${url}" target="_blank">
                                        ${text || url}
                                    </a>
                                </div>`;
                            }).join('')}
                        </div>
                    </div>
                `);
            }

            return `
                <div class="result">
                    <h2>ページ: ${result.url}</h2>
                    ${sections.join('')}
                </div>
            `;
        }).join('');

        resultsDiv.innerHTML = resultsHtml;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // エンターキーでの検索
    document.getElementById('searchText').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            searchForm.dispatchEvent(new Event('submit'));
        }
    });

    // フォームのバリデーション
    const urlInput = document.getElementById('url');
    const textInput = document.getElementById('searchText');

    urlInput.addEventListener('blur', function () {
        if (this.value && !isValidUrl(this.value)) {
            this.setCustomValidity('有効なURLを入力してください（例: https://example.com）');
        } else {
            this.setCustomValidity('');
        }
    });

    textInput.addEventListener('input', function () {
        if (this.value.length > 100) {
            this.setCustomValidity('検索テキストは100文字以内で入力してください');
        } else {
            this.setCustomValidity('');
        }
    });

    function isValidUrl(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (_) {
            return false;
        }
    }

    function loadSearchHistory() {
        fetch('/search_history')
            .then(response => response.json())
            .then(data => {
                if (data.success && data.history && data.history.length > 0) {
                    let html = '<h2>検索履歴</h2>';
                    data.history.forEach((entry, index) => {
                        html += `
                            <div class="history-item">
                                <h3>検索テキスト: ${entry.search_text}</h3>
                                <p>URL: ${entry.base_url}</p>
                                <p>検索日時: ${entry.last_updated}</p>
                                <p>検索結果数: ${entry.total_results}件</p>
                                <button class="reuse-btn" onclick="reuseSearch('${entry.search_text}', '${entry.base_url}')">この検索を再利用</button>
                            </div>
                        `;
                    });
                    searchHistoryDiv.innerHTML = html;
                } else {
                    searchHistoryDiv.innerHTML = '<div class="no-history">検索履歴はありません</div>';
                }
            })
            .catch(error => {
                console.error('検索履歴の読み込みに失敗:', error);
                searchHistoryDiv.innerHTML = '<div class="error">検索履歴の読み込みに失敗しました</div>';
            });
    }

    function reuseSearch(searchText, baseUrl) {
        // フォームの値を設定
        document.getElementById('url').value = baseUrl;
        document.getElementById('search_text').value = searchText;
        
        // 検索ボタンのテキストを更新
        const searchBtn = document.getElementById('searchBtn');
        searchBtn.textContent = '🔍 再検索';
        
        // 検索を実行
        searchForm.dispatchEvent(new Event('submit'));
    }
});

function startSearch() {
    const url = document.getElementById('url').value;
    const searchText = document.getElementById('search-text').value;
    const progress = document.getElementById('progress');
    const results = document.getElementById('results');

    if (!url || !searchText) {
        alert('URLと検索テキストを入力してください');
        return;
    }

    progress.innerHTML = '検索中...';
    results.innerHTML = '';

    fetch('/search', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url: url,
            search_text: searchText
        })
    })
        .then(response => response.json())
        .then(data => {
            progress.innerHTML = '';
            if (data.error) {
                results.innerHTML = `<div class="error">${data.error}</div>`;
                return;
            }

            if (data.results.length === 0) {
                results.innerHTML = '<div class="no-results">検索結果が見つかりませんでした。</div>';
                return;
            }

            const resultsHtml = data.results.map(result => `
            <div class="result-item">
                <h3><a href="${result.url}" target="_blank">${result.title}</a></h3>
                <p class="url">${result.url}</p>
                <p class="matches">マッチ数: ${result.matches ?? 0}</p>
                <div class="snippets">
                    ${result.snippets.map(snippet => `<p class="snippet">${snippet}</p>`).join('')}
                </div>
            </div>
        `).join('');

            results.innerHTML = resultsHtml;
        })
        .catch(error => {
            progress.innerHTML = '';
            results.innerHTML = `<div class="error">エラーが発生しました: ${error.message}</div>`;
        });
}