# Web Text Searcher

Web ページ内のテキストを検索するアプリケーションです。指定した URL のページとその配下のページを検索し、本文、head タグ、リンク内のテキストを検索します。

## 機能

- 指定した URL のページを検索
- 同じドメイン内のリンク先も自動的に検索（最大 2 階層まで）
- 本文、head タグ、リンク内のテキストを検索
- 検索結果のハイライト表示

## セットアップ

1. 必要なパッケージをインストール：

```bash
# Python 3.6以上がインストールされていることを確認
python3 --version

# 既存の仮想環境がある場合は削除
rm -rf venv

# 仮想環境の作成
python3 -m venv venv

# 仮想環境の有効化
# Windows の場合:
venv\Scripts\activate
# macOS/Linux の場合:
source venv/bin/activate

# pipのアップグレード（推奨）
python -m pip install --upgrade pip

# 依存関係のインストール
pip install -r requirements.txt
pip install flask-limiter  # 追加で必要なパッケージ
```

### トラブルシューティング

1. `Failed to fetch`エラーが発生する場合：
   - 仮想環境が正しく有効化されているか確認
   - 以下のコマンドで再セットアップ：
   ```bash
   rm -rf venv
   python3 -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   pip install flask-limiter
   ```

2. パッケージのインストールに失敗する場合：
   - インターネット接続を確認
   - プロキシ設定が必要な場合は、適切な設定を行う

## 起動方法

### 開発環境

```bash
# 仮想環境の有効化（まだ有効化していない場合）
# Windows の場合:
venv\Scripts\activate
# macOS/Linux の場合:
source venv/bin/activate

# アプリケーションの起動
python app.py
```

アプリケーションは `http://127.0.0.1:8080` でアクセスできます。

### 本番環境

```bash
source venv/bin/activate
gunicorn -w 4 -b 0.0.0.0:8080 app:app
```

## デプロイ

### 必要なファイル

```
.
├── app.py              # メインアプリケーション
├── wsgi.py            # WSGIエントリーポイント
├── requirements.txt   # 依存関係
├── static/           # CSS、JavaScript、画像
└── templates/        # HTMLテンプレート
```

### デプロイ手順

1. 必要なファイルをサーバーにアップロード
2. サーバーで仮想環境を作成し、依存関係をインストール
3. Gunicorn でアプリケーションを起動
4. Nginx などの Web サーバーと連携

## robots.txt の確認について

スクレイピングを行う前に、対象サイトの `robots.txt` を必ず確認してください。

### 確認方法

対象サイトのトップ URL の後ろに `/robots.txt` を付けるだけで確認できます。

例：

- Google: `https://www.google.com/robots.txt`
- Yahoo! JAPAN: `https://www.yahoo.co.jp/robots.txt`

### 注意すべき記述

以下のような記述がある場合、対象ページのスクレイピングは控えてください：

```txt
# 全面禁止
User-agent: *
Disallow: /

# 一部禁止
User-agent: *
Disallow: /private/
Disallow: /admin/

# 特定のクローラーだけ禁止
User-agent: Googlebot
Disallow: /
```

robots.txt は技術的な制限ではなく、クローラーに対するマナーガイドです。
スクレイピングできる＝許可されている、ではありません。
利用規約と併せて必ず確認し、トラブルにならないよう注意しましょう。
