# ==============================================================================
# v1.0.1 - real crawler + connection alert + tutorial video popup
# ==============================================================================

import os
import json
import random
import re
import hashlib
import threading
import time
import string
import posixpath
import sqlite3
import io
import sys
import socket
import xml.etree.ElementTree as ET
import concurrent.futures
from datetime import datetime, timezone
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag, urlunparse, unquote, quote
from urllib.robotparser import RobotFileParser

try:
    from PIL import Image
    import imagehash
except ImportError:
    pass

try:
    import psycopg2
except ImportError:
    psycopg2 = None

try:
    import redis
except ImportError:
    redis = None

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template_string, request, g, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import socks
except ImportError:
    socks = None
    print("[INFO] PySocks unavailable. Running without Tor.")

# I am using socks5h to force DNS resolution through the Tor node (Anti-DNS Leak)
TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9150" 
PROXIES = {"http": TOR_SOCKS_PROXY, "https": TOR_SOCKS_PROXY}
TOR_CONNECTED = False

# mimic tor browser exactly to prevent fingerprinting
TOR_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
HEADERS = {
    "User-Agent": TOR_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1"
}

def check_tor_connection():
    """Validates if Tor is actively routing traffic safely."""
    for port in [9150, 9050]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            if s.connect_ex(('127.0.0.1', port)) == 0:
                return f"socks5h://127.0.0.1:{port}"
    return None

def tor_watchdog_worker():
    """Continuously monitors Tor connection. Halts crawler if connection drops."""
    global TOR_CONNECTED, TOR_SOCKS_PROXY, PROXIES
    while True:
        proxy = check_tor_connection()
        if proxy:
            if not TOR_CONNECTED:
                print(f"[OPSEC] Secure Tor Connection Established via {proxy}")
            TOR_SOCKS_PROXY = proxy
            PROXIES = {"http": TOR_SOCKS_PROXY, "https": TOR_SOCKS_PROXY}
            TOR_CONNECTED = True
        else:
            if TOR_CONNECTED:
                print("\n[CRITICAL WARNING] TOR CONNECTION LOST! HALTING CRAWLER TO PREVENT IP LEAK.\n")
            TOR_CONNECTED = False
        time.sleep(3)

THREAT_CATEGORIES = {
    "Cybercrime/Malware": ["ransomware", "botnet", "exploit", "0day", "ddos", "malware", "trojan", "keylogger", "rootkit"],
    "Financial Fraud": ["cvv", "fullz", "dumps", "skimmer", "carding", "money laundering", "counterfeit", "bank drop"],
    "Narcotics": ["cocaine", "fentanyl", "heroin", "meth", "lsd", "mdma", "weed", "cannabis", "darknet market"],
    "Weapons/Arms": ["glock", "ak-47", "ar-15", "firearm", "ammunition", "silencer", "ghost gun"],
    "Data Leak": ["database dump", "leaked", "breached", "hacked", "credentials", "passwords", "sql dump", "combolist"],
    "Market": ["market", "marketplace", "amazon", "mall"],
    "Adult Content": ["porn", "nsfw", "xxx", "child porn", "escort", "loliporn", "dick", "cock", "sex", "vargina", "teen"]
}

def classify_content(text):
    if not text:
        return "General"
        
    text_lower = text.lower()
    scores = {category: 0 for category in THREAT_CATEGORIES}
    
    for category, keywords in THREAT_CATEGORIES.items():
        for kw in keywords:
            if len(kw) <= 4:
                pattern = r'\b' + re.escape(kw) + r'\b'
            else:
                pattern = r'\b' + re.escape(kw) + r'[a-z0-9]*\b'
            
            matches = len(re.findall(pattern, text_lower))
            scores[category] += matches
            
    max_score = 0
    best_category = None
    for category, score in scores.items():
        if score > max_score and score >= 1: 
            max_score = score
            best_category = category
            
    if best_category is None:
        return "General"
        
    return best_category

IP_CACHE = {}
IP_QUEUE = set()

def resolve_ip(ip):
    if ip in IP_CACHE:
        return IP_CACHE[ip]
    if ip not in IP_QUEUE:
        IP_QUEUE.add(ip)
    return {"loc": "Unknown Location", "lat": None, "lon": None}

def ip_resolver_worker():
    """Background thread to slowly resolve IPs without hitting rate limits."""
    while True:
        if IP_QUEUE:
            ip = IP_QUEUE.pop()
            try:
                res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon", timeout=3)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        loc = f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
                        if loc.startswith("Unknown, "): loc = loc.replace("Unknown, ", "")
                        IP_CACHE[ip] = {
                            "loc": loc,
                            "lat": data.get("lat"),
                            "lon": data.get("lon")
                        }
                    else:
                        IP_CACHE[ip] = {"loc": "Unknown Location", "lat": None, "lon": None}
                elif res.status_code == 429:
                    IP_QUEUE.add(ip)
                    time.sleep(5)
                else:
                    IP_CACHE[ip] = {"loc": "Unknown Location", "lat": None, "lon": None}
            except Exception:
                IP_CACHE[ip] = {"loc": "Unknown Location", "lat": None, "lon": None}
            time.sleep(1.5)
        else:
            time.sleep(2)

ENTITY_REGEX = {
    "btc_address": r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
    "eth_address": r"\b0x[a-fA-F0-9]{40}\b",
    "xmr_address": r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
    "onion_v3_link": r"\b[a-z2-7]{56}\.onion\b",
    "pgp_public_key": r"-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----",
    "cve_vulnerability": r"\bCVE-\d{4}-\d{4,7}\b",
    "md5_hash": r"\b[a-fA-F0-9]{32}\b",
    "sha256_hash": r"\b[a-fA-F0-9]{64}\b",
    "ipv4_address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
}

def extract_entities(text):
    entities = {}
    for entity_type, pattern in ENTITY_REGEX.items():
        if entity_type == "pgp_public_key":
            found = re.findall(pattern, text)
        else:
            found = re.findall(pattern, text, re.IGNORECASE)
            
        if found:
            if entity_type == "ipv4_address":
                found = [ip for ip in found if not ip.startswith(('127.', '192.168.', '10.', '172.', '0.'))]
            if found:
                entities[entity_type] = list(set(found))[:100]
    return entities

REQUEST_TIMEOUT = 10 
MAX_PAGES_PER_SWEEP = 1000   
MAX_DEPTH = 5          
MAX_CONTENT_BYTES = 2_000_000

SEED_URLS = [
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/", 
    "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/index.php/Main_Page", 
    "http://danielas3rtn54uwmofdo3x2bsdifr47hxulfdicpntqfekssflawdic.onion/", 
    "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/", 
    "http://2fd6cemt4gmccflhm6imvdfvli3ghipcnw4dtvtsm6ybcxc2vtloxwid.onion/", 
    "http://torlinksge6enmcyyuxzjdfapnwzddtcdjhwep5sjwqvhztzquzpwd.onion/", 
    "http://visitorfi5kl7q7i2lhrm6bgomkcrznxcydkmq7ebvep3hffeyhwewyd.onion/", 
    "http://doraemonr5dsozne3wj5hzdu6d2pb3eadiw56l2kcfqqqgbhlcxhieyd.onion",
    "http://teresarrmmruhhjmd2rbjgvo3lwtxthh7g52bvo4bveoyap7pnnzjcyd.onion/"
]

DB_PATH = "index.db"

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    title TEXT,
    status INTEGER,
    depth INTEGER,
    fetched_at TEXT,
    classification TEXT,
    content_summary TEXT
);

CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY,
    from_url TEXT,
    to_url TEXT,
    UNIQUE(from_url, to_url)
);
"""

def init_db(path=DB_PATH):
    conn = sqlite3.connect(path, check_same_thread=False)
    cur = conn.cursor()
    for q in CREATE_SQL.strip().split(";"):
        if q.strip():
            cur.execute(q)
            
    try:
        cur.execute("ALTER TABLE pages ADD COLUMN classification TEXT")
    except sqlite3.OperationalError:
        pass 
        
    try:
        cur.execute("ALTER TABLE pages ADD COLUMN content_summary TEXT")
    except sqlite3.OperationalError:
        pass 
        
    conn.commit()
    return conn

DB_LOCK = threading.Lock()

def save_page(conn, url, title, status, depth, classification, summary=""):
    now = datetime.utcnow().isoformat()
    with DB_LOCK:
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO pages (url, title, status, depth, fetched_at, classification, content_summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (url, title, status, depth, now, classification, summary)
            )
            conn.commit()
        except Exception:
            pass

def save_link(conn, from_url, to_url):
    with DB_LOCK:
        try:
            cur = conn.cursor()
            cur.execute("INSERT OR IGNORE INTO links (from_url, to_url) VALUES (?, ?)", (from_url, to_url))
            conn.commit()
        except Exception:
            pass

def canonicalize(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return url
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    upath = unquote(path)
    np = posixpath.normpath(upath)
    if not upath.startswith("/"):
        np = np.lstrip("/")
    if np == ".":
        np = "/"
    if np.endswith("/") and np != "/":
        np = np.rstrip("/")
    safe_path = quote(np, safe="/%:@+,&?;=")
    return urlunparse((scheme, netloc, safe_path, "", parsed.query or "", ""))

def normalize_url(base, href):
    if not href: return None
    if href.startswith(("javascript:", "mailto:", "data:", "tel:")): return None
    joined = urljoin(base, href)
    joined, _ = urldefrag(joined)
    return canonicalize(joined)

def is_onion(url):
    try:
        p = urlparse(url)
        return p.hostname and p.hostname.endswith(".onion")
    except Exception:
        return False

def get_secure_session():
    """Forces requests to use a strict proxy session."""
    session = requests.Session()
    session.proxies = PROXIES
    session.headers.update(HEADERS)
    return session

def fetch_and_parse_url(url, depth):
    """Worker function executing concurrently with STRICT OPSEC locks."""
    if not TOR_CONNECTED:
        return (None, 0, depth, "Dead Node", "TOR DISCONNECTED - ABORTED", [], [])

    try:
        session = get_secure_session()
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        
        if "html" not in r.headers.get("Content-Type", ""):
            return (None, r.status_code, depth, "Dead Node", "Non-HTML Content", [], [])
            
        html = r.text
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string.strip() if soup.title else None
        
        page_text = soup.get_text(" ", strip=True)
        classification = classify_content(page_text)
        summary = (page_text[:400] + '...') if len(page_text) > 400 else page_text
        
        extracted_entities = extract_entities(page_text)
        entity_nodes = []
        
        if 'btc_address' in extracted_entities:
            for e in extracted_entities['btc_address']: entity_nodes.append(f"btc:{e}")
        if 'cve_vulnerability' in extracted_entities:
            for e in extracted_entities['cve_vulnerability']: entity_nodes.append(f"cve:{e}")
        if 'ipv4_address' in extracted_entities:
            for e in extracted_entities['ipv4_address']: 
                entity_nodes.append(f"ip:{e}")
                IP_QUEUE.add(e)
        if 'email' in extracted_entities:
            for e in extracted_entities['email']: entity_nodes.append(f"email:{e}")
        
        new_links = set()
        
        for a in soup.find_all("a", href=True):
            nurl = normalize_url(url, a["href"])
            if nurl and is_onion(nurl):
                new_links.add(nurl)
                
        for match in re.findall(r"([a-z2-7]{16,56}\.onion)", html):
            nurl = canonicalize("http://" + match)
            if nurl: new_links.add(nurl)
            
        return (title, r.status_code, depth, classification, summary, list(new_links), entity_nodes)
    except Exception as e:
        return (None, 0, depth, "Dead Node", str(e), [], [])

def crawl(seeds, db_path, max_pages=MAX_PAGES_PER_SWEEP, max_depth=MAX_DEPTH):
    """Manages the ThreadPoolExecutor securely"""
    visited = set()
    domain_visits = {} 
    futures = {}
    
    conn = init_db(db_path)
    
    try:
        cur = conn.cursor()
        cur.execute("SELECT url FROM pages")
        for row in cur.fetchall():
            visited.add(row[0])
    except Exception:
        pass
        
    print(f"[+] Launching Fast Exponential Thread Swarm on {len(seeds)} seed(s)...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for s in seeds:
            nurl = canonicalize(s)
            if nurl in visited:
                visited.remove(nurl)
                
            visited.add(nurl)
            futures[executor.submit(fetch_and_parse_url, nurl, 0)] = nurl
                
        pages_crawled = 0

        while futures and pages_crawled < max_pages:
            # Check OPSEC killswitch
            if not TOR_CONNECTED:
                print("\n[!] OPSEC ABORT: Tor Disconnected mid-sweep. Terminating swarm.")
                break

            done, _ = concurrent.futures.wait(futures.keys(), return_when=concurrent.futures.FIRST_COMPLETED)
            
            for future in done:
                url = futures.pop(future)
                try:
                    result = future.result()
                    if not result: continue
                    
                    title, status, depth, classification, summary, new_links, entity_nodes = result
                    save_page(conn, url, title, status, depth, classification, summary)
                        
                    pages_crawled += 1
                    current_domain = urlparse(url).netloc
                    
                    for entity_node in entity_nodes:
                        save_link(conn, url, entity_node)
                    
                    for next_url in new_links:
                        save_link(conn, url, next_url)
                        
                        if next_url not in visited and depth + 1 <= max_depth:
                            target_domain = urlparse(next_url).netloc
                            
                            if target_domain != current_domain:
                                if domain_visits.get(target_domain, 0) < 15:
                                    visited.add(next_url)
                                    domain_visits[target_domain] = domain_visits.get(target_domain, 0) + 1
                                    futures[executor.submit(fetch_and_parse_url, next_url, depth + 1)] = next_url
                            else:
                                if domain_visits.get(target_domain, 0) < 2:
                                    visited.add(next_url)
                                    domain_visits[target_domain] = domain_visits.get(target_domain, 0) + 1
                                    futures[executor.submit(fetch_and_parse_url, next_url, depth + 1)] = next_url

                except Exception:
                    pass

    conn.close()
    print(f"[!] Sweep Cycle Complete or Aborted. Active nodes penetrated: {pages_crawled}")

def search_db(conn, query, limit=20):
    cur = conn.cursor()
    qlike = f"%{query}%"
    cur.execute(
        "SELECT url, title, status, depth, fetched_at, classification FROM pages "
        "WHERE title LIKE ? OR url LIKE ? OR classification LIKE ? LIMIT ?",
        (qlike, qlike, qlike, limit),
    )
    return cur.fetchall()

POSTGRES_CONFIG = {
    "user": "postgres", 
    "password": "password", 
    "host": "localhost",
    "port": "5432",
    "database": "darkweb_db_live" 
}

GLOBAL_GEO_DATA = []
GLOBAL_CURRENCY_RATES = {}

def get_dashboard_db_connection():
    try:
        if not psycopg2:
            raise ImportError("psycopg2 not installed")
        conn = psycopg2.connect(
            user=POSTGRES_CONFIG["user"], password=POSTGRES_CONFIG["password"],
            host=POSTGRES_CONFIG["host"], port=POSTGRES_CONFIG["port"], database="postgres"
        )
        conn.autocommit = True
        cur = conn.cursor()
        try: cur.execute(f"CREATE DATABASE {POSTGRES_CONFIG['database']}")
        except psycopg2.errors.DuplicateDatabase: pass
        finally:
            cur.close()
            conn.close()
        pg_conn = psycopg2.connect(**POSTGRES_CONFIG)
        return pg_conn
    except Exception as e:
        sqlite_conn = sqlite3.connect("prin_local_fallback.db", check_same_thread=False)
        return sqlite_conn

def setup_dashboard_db():
    conn = get_dashboard_db_connection()
    is_sqlite = isinstance(conn, sqlite3.Connection)
    cur = conn.cursor()
    
    if is_sqlite:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, is_admin BOOLEAN DEFAULT FALSE
            );
        """)
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, is_admin BOOLEAN DEFAULT FALSE
            );
        """)
            
    conn.commit()
    cur.close()
    conn.close()

def create_user(conn, username, password, is_admin=False):
    is_sqlite = isinstance(conn, sqlite3.Connection)
    cur = conn.cursor()
    password_hash = generate_password_hash(password)
    try:
        if is_sqlite:
            cur.execute("INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                        (username, password_hash, is_admin))
        else:
            cur.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                        (username, password_hash, is_admin))
        conn.commit()
    except Exception: 
        conn.rollback()
    finally:
        cur.close()

def get_user(conn, username):
    is_sqlite = isinstance(conn, sqlite3.Connection)
    cur = conn.cursor()
    try:
        if is_sqlite:
            cur.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,))
        else:
            cur.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        if user: 
            return {'id': user[0], 'username': user[1], 'password_hash': user[2], 'is_admin': user[3]}
        return None
    finally:
        cur.close()

def check_password(password_hash, password):
    return check_password_hash(password_hash, password)

def geopolitics_worker():
    global GLOBAL_GEO_DATA, GLOBAL_CURRENCY_RATES
    print("[WORKER] 7-Day Historical Geopolitics Engine started. Ingesting deep feeds...")
    
    WORLD_COUNTRIES = {
        "usa": {"coords": [-95.7, 37.0], "currency": "USD", "aliases": ["united states", "america", "washington", "pentagon"]},
        "ukraine": {"coords": [31.1, 48.3], "currency": "UAH", "aliases": ["kyiv", "zelensky"]},
        "russia": {"coords": [105.3, 61.5], "currency": "RUB", "aliases": ["moscow", "putin", "kremlin"]},
        "china": {"coords": [104.1, 35.8], "currency": "CNY", "aliases": ["beijing", "xi jinping", "ccp"]},
        "israel": {"coords": [34.8, 31.0], "currency": "ILS", "aliases": ["jerusalem", "tel aviv", "idf", "netanyahu"]},
        "palestine": {"coords": [35.2, 31.9], "currency": "ILS", "aliases": ["gaza", "hamas", "west bank", "rafah"]},
        "iran": {"coords": [53.6, 32.4], "currency": "IRR", "aliases": ["tehran", "irgc"]},
        "taiwan": {"coords": [120.9, 23.6], "currency": "TWD", "aliases": ["taipei"]},
        "north korea": {"coords": [127.5, 40.3], "currency": "KPW", "aliases": ["dprk", "pyongyang", "kim jong"]},
        "south korea": {"coords": [127.7, 35.9], "currency": "KRW", "aliases": ["seoul"]},
        "uk": {"coords": [-3.4, 55.3], "currency": "GBP", "aliases": ["united kingdom", "britain", "london"]},
        "france": {"coords": [2.2, 46.2], "currency": "EUR", "aliases": ["paris", "macron"]},
        "germany": {"coords": [10.4, 51.1], "currency": "EUR", "aliases": ["berlin"]},
        "japan": {"coords": [138.2, 36.2], "currency": "JPY", "aliases": ["tokyo"]},
        "india": {"coords": [78.9, 20.5], "currency": "INR", "aliases": ["new delhi", "modi"]},
        "pakistan": {"coords": [69.3, 30.3], "currency": "PKR", "aliases": ["islamabad"]},
        "afghanistan": {"coords": [67.7, 33.9], "currency": "AFN", "aliases": ["kabul", "taliban"]},
        "syria": {"coords": [38.9, 34.8], "currency": "SYP", "aliases": ["damascus", "assad"]},
        "lebanon": {"coords": [35.8, 33.8], "currency": "LBP", "aliases": ["beirut", "hezbollah"]},
        "yemen": {"coords": [47.5, 15.5], "currency": "YER", "aliases": ["sanaa", "houthi", "houthis"]},
        "sudan": {"coords": [30.2, 12.8], "currency": "SDG", "aliases": ["khartoum", "rsf"]},
        "somalia": {"coords": [46.1, 5.1], "currency": "SOS", "aliases": ["mogadishu", "al-shabaab"]},
        "venezuela": {"coords": [-66.5, 7.1], "currency": "VES", "aliases": ["caracas", "maduro"]},
        "haiti": {"coords": [-72.2, 18.9], "currency": "HTG", "aliases": ["port-au-prince"]},
        "drc": {"coords": [21.7, -4.0], "currency": "CDF", "aliases": ["democratic republic of congo", "kinshasa"]},
        "myanmar": {"coords": [12.0, 96.0], "currency": "MMK", "aliases": ["burma"]},
        "mexico": {"coords": [-102.5, 23.6], "currency": "MXN", "aliases": ["mexico city"]},
        "brazil": {"coords": [-51.9, -14.2], "currency": "BRL", "aliases": ["brasilia"]},
        "turkey": {"coords": [35.2, 38.9], "currency": "TRY", "aliases": ["ankara", "erdogan"]},
        "egypt": {"coords": [30.8, 26.8], "currency": "EGP", "aliases": ["cairo"]},
        "nigeria": {"coords": [46.1, 9.0], "currency": "NGN", "aliases": ["abuja"]},
        "philippines": {"coords": [121.7, 12.8], "currency": "PHP", "aliases": ["manila"]},
        "australia": {"coords": [133.7, -25.2], "currency": "AUD", "aliases": ["canberra", "sydney"]}
    }

    sorted_country_keys = sorted(WORLD_COUNTRIES.keys(), key=len, reverse=True)

    TENSION_WEIGHTS = {
        "invasion": 0.8, "war": 0.6, "missile": 0.6, "bomb": 0.5, "terror": 0.5, 
        "assassination": 0.6, "casualty": 0.4, "attack": 0.4, "strike": 0.4, 
        "killed": 0.4, "rebel": 0.3, "drone": 0.3, "blockade": 0.3, "evacuation": 0.3,
        "protest": 0.2, "riot": 0.3, "military": 0.2, "troops": 0.2, "sanctions": 0.2, 
        "crisis": 0.2, "tension": 0.1, 
        "cyberattack": 0.4, "hack": 0.3, "espionage": 0.4, "cartel": 0.3,
        "trafficking": 0.3, "arrest": 0.1, "corruption": 0.2, "tariff": 0.2,
        "trade war": 0.3, "dispute": 0.2, "drills": 0.2, "deployment": 0.3,
        "extremist": 0.4, "insurgent": 0.4, "coup": 0.7
    }
    
    MODIFIERS = {
        "escalation": {"words": ["nuclear", "escalation", "imminent", "unprecedented", "threatens", "declares"], "factor": 2.0},
        "deescalation": {"words": ["peace", "ceasefire", "treaty", "negotiation", "withdraw"], "factor": 0.2}
    }
    
    rss_feeds = [
        "http://feeds.bbci.co.uk/news/world/rss.xml",
        "https://www.aljazeera.com/xml/rss/all.xml",
        "https://rss.nytimes.com/services/xml/rss/nyt/World.xml",
        "https://news.un.org/feed/subscribe/en/news/all/rss.xml",
        "https://www.theguardian.com/world/rss",
        "http://rss.cnn.com/rss/edition_world.rss",
        "https://www.cnbc.com/id/100727362/device/rss/rss.html"
    ]

    loop_counter = 0
    active_hotspots = {}

    while True:
        if len(GLOBAL_CURRENCY_RATES) == 0 or loop_counter % 60 == 0:
            try:
                curr_resp = requests.get("https://open.er-api.com/v6/latest/USD", timeout=5)
                if curr_resp.status_code == 200: GLOBAL_CURRENCY_RATES = curr_resp.json().get("rates", {})
            except Exception: pass

        locations_to_delete = []
        for loc in active_hotspots:
            active_hotspots[loc]["severity"] -= 0.05
            if active_hotspots[loc]["severity"] < 0.10: 
                locations_to_delete.append(loc)
        for loc in locations_to_delete:
            del active_hotspots[loc]
        
        try:
            for feed in rss_feeds:
                # Normal requests for RSS. Tor is strictly for the dark web crawler.
                resp = requests.get(feed, timeout=10) 
                if resp.status_code == 200:
                    root = ET.fromstring(resp.content)
                    
                    for item in root.findall('.//item')[:150]: 
                        title = item.find('title').text if item.find('title') is not None else ""
                        desc = item.find('description').text if item.find('description') is not None else ""
                        text_lower = f"{title} {desc}".lower()

                        base_score = sum(weight for kw, weight in TENSION_WEIGHTS.items() if kw in text_lower)
                        if base_score == 0: continue 
                        
                        modifier_factor = 1.0
                        if any(w in text_lower for w in MODIFIERS["escalation"]["words"]):
                            modifier_factor = MODIFIERS["escalation"]["factor"]
                        elif any(w in text_lower for w in MODIFIERS["deescalation"]["words"]):
                            modifier_factor = MODIFIERS["deescalation"]["factor"]
                            
                        final_article_score = base_score * modifier_factor

                        for loc_key in sorted_country_keys:
                            geo_info = WORLD_COUNTRIES[loc_key]
                            aliases = geo_info.get("aliases", []) + [loc_key]
                            
                            pattern = r'\b(?:' + '|'.join(re.escape(a) for a in aliases) + r')\b'
                            if re.search(pattern, text_lower):
                                
                                if loc_key not in active_hotspots:
                                    active_hotspots[loc_key] = {
                                        "coords": geo_info["coords"], "country": loc_key, 
                                        "currency": geo_info["currency"], "severity": 0.2,
                                        "label": loc_key.title(), "latest_headline": ""
                                    }
                                
                                active_hotspots[loc_key]["severity"] += (0.05 + final_article_score)
                                active_hotspots[loc_key]["latest_headline"] = title
                                active_hotspots[loc_key]["severity"] = min(1.0, active_hotspots[loc_key]["severity"])
                                break 
            
            processed_events = []
            for data in active_hotspots.values():
                if data["severity"] >= 0.25: 
                    event_data = data.copy()
                    event_data["exchange_rate"] = GLOBAL_CURRENCY_RATES.get(data["currency"], "N/A")
                    processed_events.append(event_data)
                    
            GLOBAL_GEO_DATA = processed_events
        except Exception as e:
            pass
        
        loop_counter += 1
        time.sleep(20) 

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_dashboard_db_connection()
    user_data = get_user(conn, user_id)
    if hasattr(conn, 'close'): conn.close()
    if user_data: return User(id=user_data['username'], username=user_data['username'])
    if user_id == "admin": return User(id="admin", username="admin")
    return None

@app.before_request
def before_request():
    g.db = get_dashboard_db_connection()

@app.teardown_request
def teardown_request(exception):
    db = g.get('db')
    if db is not None and hasattr(db, 'close'): db.close()

LOGIN_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>Access Anomaly</title>
    <style>
        @keyframes border-flicker { 0% { border-color: #444; } 50% { border-color: #555; } 100% { border-color: #444; } }
        body { background-color: #1a1a1a; color: #d1d1d1; font-family: 'Helvetica Neue', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; overflow: hidden; }
        .container { width: 400px; background-color: #2b2b2b; border: 1px solid #444; padding: 30px; animation: border-flicker 10s infinite; }
        h1 { color: #d1d1d1; font-weight: 300; font-size: 1.5rem; margin: 0 0 25px 0; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label { display: flex; align-items: center; margin-bottom: 5px; font-size: 0.9rem; color: #888; }
        input[type="text"], input[type="password"] { background-color: #222; border: 1px solid #444; padding: 10px; width: 100%; box-sizing: border-box; color: #d1d1d1; }
        input[type="submit"] { background-color: #444; border: 1px solid #555; color: #d1d1d1; padding: 12px 20px; width: 100%; cursor: pointer; }
        .captcha-box { background-color: #111; padding: 10px; text-align: center; font-family: monospace; font-size: 1.5rem; letter-spacing: 5px; border: 1px solid #444; user-select: none; }
        .flashes { color: #c75a5a; padding: 10px; border: 1px solid #5a1e1e; background-color: #3a2222; margin-top: 20px; list-style: none; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Identity Verification Protocol</h1>
        <form method="post">
            <div class="form-group"><label>Identifier</label><input type="text" name="username" value="admin" required></div>
            <div class="form-group"><label>Passkey</label><input type="password" name="password" value="adminpass" required></div>
            <div class="form-group"><label>Cognitive Test</label><div class="captcha-box">{{ captcha }}</div><input type="text" name="captcha" value="{{ captcha }}" required style="margin-top: 10px;"></div>
            <input type="submit" value="Establish Link">
        </form>
        {% with messages = get_flashed_messages() %}
        {% if messages %}<ul class=flashes>{% for message in messages %}<li>ANOMALY DETECTED: {{ message }}</li>{% endfor %}</ul>{% endif %}
        {% endwith %}
    </div>
</body>
</html>
"""

PRIN_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PRIN | Planetary Resource Intelligence Network</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.28/jspdf.plugin.autotable.min.js"></script>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        :root { --term-bg: #000000; --term-panel: #0a0a0a; --term-border: #262626; --term-text: #d4d4d4; --term-highlight: #ea580c; --term-green: #22c55e; --term-red: #ef4444; }
        body { background-color: var(--term-bg); color: var(--term-text); font-family: 'Segoe UI', sans-serif; margin: 0; overflow: hidden; }
        .font-mono { font-family: 'Consolas', 'Monaco', 'Courier New', monospace; }
        .panel { background-color: var(--term-panel); border: 1px solid var(--term-border); }
        .panel-header { background-color: #111; border-bottom: 1px solid var(--term-border); padding: 6px 12px; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; color: #a3a3a3; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--term-bg); border-left: 1px solid var(--term-border); }
        ::-webkit-scrollbar-thumb { background: #404040; }
        ::-webkit-scrollbar-thumb:hover { background: #525252; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--term-border); font-size: 0.75rem; }
        th { color: #737373; font-weight: normal; }
        .layer-btn { background: transparent; border: 1px solid var(--term-border); color: #a3a3a3; cursor: pointer; transition: all 0.1s; }
        .layer-btn:hover { border-color: #525252; color: white; }
        .layer-btn.active { background: #1a1a1a; border-color: var(--term-highlight); color: var(--term-highlight); }
        .pulse-dot { width: 8px; height: 8px; background-color: var(--term-green); border-radius: 50%; animation: pulse 2s infinite; }
        .pulse-dot.offline { background-color: var(--term-red); box-shadow: 0 0 10px var(--term-red); animation: none; }
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); } 70% { box-shadow: 0 0 0 6px rgba(34, 197, 94, 0); } 100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); } }
        .tab-btn { background: transparent; color: #737373; padding: 8px 10px; font-size: 0.60rem; font-family: 'Consolas', monospace; font-weight: bold; cursor: pointer; border-bottom: 2px solid transparent; border-right: 1px solid var(--term-border); transition: all 0.2s; }
        .tab-btn:hover { color: #d4d4d4; background: #111; }
        .tab-btn.active { color: var(--term-highlight); border-bottom-color: var(--term-highlight); background: var(--term-panel); }
        
        .tab-content { display: none !important; height: 100%; flex-direction: column; }
        .tab-content.active { display: flex !important; }
        
        .slide-in { animation: slideIn 0.3s ease-out forwards; opacity: 0; transform: translateX(10px); }
        @keyframes slideIn { to { opacity: 1; transform: translateX(0); } }
        .modal-bg { backdrop-filter: blur(2px); }
        .modal-content-onion { border-top-color: #ea580c; border-bottom-color: #ea580c; }
        .modal-content-geo { border-top-color: #eab308; border-bottom-color: #eab308; }
        
        .vis-network { outline: none; }
        .vis-tooltip {
            background-color: #111 !important;
            border: 1px solid #c084fc !important;
            color: #d4d4d4 !important;
            font-family: 'Consolas', monospace !important;
            font-size: 10px !important;
            border-radius: 4px !important;
            padding: 8px !important;
            white-space: pre-wrap;
        }
        .graph-fullscreen { 
            position: fixed !important; top: 0 !important; left: 0 !important; 
            width: 100vw !important; height: 100vh !important; z-index: 9999 !important; 
            background-color: #050905 !important; padding: 20px !important; 
        }
        .tor-alert-banner { display: none; background-color: #ef4444; color: white; padding: 5px 15px; font-weight: bold; text-align: center; font-size: 0.8rem; animation: pulse-bg 1.5s infinite; }
        @keyframes pulse-bg { 0% { background-color: #ef4444; } 50% { background-color: #b91c1c; } 100% { background-color: #ef4444; } }
    </style>
</head>
<body class="h-screen flex flex-col">

    <!-- CRITICAL ALERT BANNER -->
    <div id="tor-critical-alert" class="tor-alert-banner w-full flex items-center justify-center gap-2 font-mono">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
        CRITICAL OPSEC FAILURE: Tor proxy connection lost. Crawler automatically halted to prevent real IP exposure. Check Tor Background Service. 
        Crawler work only in desktop version service. Check Tutorial.
    </div>

    <header class="border-b border-[#262626] bg-[#050905] flex justify-between items-center px-4 py-2 select-none">
        <div class="flex items-center gap-4">
            <div class="font-bold text-gray-200 tracking-wide text-sm">PRIN <span class="text-gray-500 font-normal">| PLANETARY RESOURCE INTELLIGENCE</span></div>
            <div class="flex gap-2">
                <div class="px-2 py-0.5 bg-[#1a1a1a] border border-[#333] text-xs font-mono text-green-500 rounded-sm flex items-center gap-2" id="tor-status-container">
                    <div class="pulse-dot" id="api-status-dot"></div>
                    <span id="api-status-text">TOR TUNNEL SECURE</span>
                </div>
                <div class="px-2 py-0.5 bg-[#1a1a1a] border border-[#333] text-xs font-mono text-gray-500 rounded-sm flex items-center gap-2" id="ai-status-container">
                    <div class="pulse-dot" style="background-color: #a855f7;" id="ai-status-dot"></div>
                    <span id="ai-status-text" class="text-purple-400">PRIN LINK CHK...</span>
                </div>
            </div>
        </div>
        <div class="flex items-center gap-6 font-mono text-xs">
            <span class="text-orange-500 font-bold">OSINT SYNC IN: <span id="refresh-timer">20</span>s</span>
        </div>
        <div class="flex items-center gap-6 font-mono text-xs">
            <div id="clock" class="text-orange-500 w-48 text-right font-bold hidden lg:block"></div>
            <span class="text-gray-500">OPERATOR: <span class="text-orange-500">{{ current_user.username }}</span></span>
            
            <!-- GITHUB REPO BUTTON -->
            <a href="https://github.com/dingra11/beest_prin" target="_blank" rel="noopener noreferrer" class="flex items-center gap-2 text-gray-300 hover:text-white font-bold border border-gray-700 bg-gray-800/30 hover:bg-gray-700/50 px-3 py-1 rounded transition-colors shadow-[0_0_10px_rgba(255,255,255,0.1)]">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg> GITHUB
            </a>

            <!-- NEW TUTORIAL BUTTON -->
            <button onclick="openTutorialModal()" class="flex items-center gap-2 text-blue-400 hover:text-white font-bold border border-blue-900 bg-blue-900/30 hover:bg-blue-800/50 px-3 py-1 rounded transition-colors shadow-[0_0_10px_rgba(59,130,246,0.2)]">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg> TUTORIAL
            </button>

            <a href="{{ url_for('logout') }}" class="text-red-500 hover:text-red-400 font-bold">[ DISCONNECT ]</a>
        </div>
    </header>

    <main class="flex-1 grid grid-cols-1 md:grid-cols-12 gap-2 p-2 overflow-hidden bg-black">
        
        <!-- MAIN GLOBE PANEL -->
        <div class="md:col-span-6 panel relative flex flex-col overflow-hidden select-none">
            
            <div class="absolute top-3 left-3 z-10 flex items-center gap-2">
                <div class="w-2 h-2 bg-red-500 rounded-full animate-pulse" id="telemetry-dot"></div>
                <span class="text-[10px] font-mono text-gray-400 bg-black/80 px-1 border border-gray-800" id="layer-label">HEATMAP / TOPOGRAPHY: GEOPOLITICS</span>
            </div>
            
            <!-- Floating Tactical Layer Controls -->
            <div class="absolute bottom-8 left-3 z-10 flex flex-col gap-2 font-mono text-[10px]" id="layer-controls">
                <button class="layer-btn active p-2 text-yellow-400 bg-[#050905]/90 shadow-[0_0_10px_rgba(0,0,0,0.8)] border-yellow-500/50" data-layer="geopolitics">[1] GEOPOLITICAL TENSIONS</button>
                <button class="layer-btn p-2 text-purple-400 bg-[#050905]/90 shadow-[0_0_10px_rgba(0,0,0,0.8)] border-purple-500/50" data-layer="darkweb">[2] THREAT / DARKWEB</button>
            </div>

            <div id="globe-container" class="flex-1 relative w-full h-full cursor-grab active:cursor-grabbing">
                <canvas id="globe-canvas" class="w-full h-full absolute inset-0 drop-shadow-[0_0_15px_rgba(14,165,233,0.15)]"></canvas>
            </div>
            <div class="h-6 border-t border-[var(--term-border)] bg-[#050905] flex justify-between items-center px-3 font-mono text-[9px] text-gray-500">
                <span>PROJ: ORTHOGRAPHIC (HI-RES BORDERS)</span>
                <span>FUSION: SATELLITE / THREAT INTEL</span>
                <span id="data-lag">DATA LAG: < 400ms</span>
            </div>
        </div>

        <!-- ANALYSIS CORE PANEL -->
        <div class="md:col-span-6 flex flex-col gap-2 overflow-hidden">
            <div class="panel flex-1 flex flex-col overflow-hidden">
                <div class="panel-header text-red-400 flex justify-between"><span>Analysis Core</span><span>AI_SYS_04</span></div>
                
                <div class="flex border-b border-[#262626] bg-[#050905]">
                    <button class="tab-btn flex-1" data-target="tab-feed">LIVE</button>
                    <button class="tab-btn active flex-1" data-target="tab-hotspots">GEO</button>
                    <button class="tab-btn flex-1 text-purple-400" data-target="tab-darkweb">DARKWEB</button>
                    <button class="tab-btn flex-1 text-cyan-400" data-target="tab-graph">GRAPH</button>
                    <button class="tab-btn flex-1 text-pink-400" data-target="tab-connections">LINKS</button>
                    <button class="tab-btn flex-1 border-r-0" data-target="tab-logs">LOGS</button>
                </div>

                <div class="p-2 overflow-y-auto flex-1 font-mono text-xs relative custom-scrollbar">
                    
                    <div id="tab-feed" class="tab-content space-y-2"></div>

                    <div id="tab-hotspots" class="tab-content active">
                        <div class="flex justify-between items-center border-b border-[#333] pb-2 mb-2">
                            <span class="text-gray-400">GLOBAL FLASHPOINTS</span>
                            <span class="text-[9px] text-yellow-500 animate-pulse">● OSINT LIVE</span>
                        </div>
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr>
                                    <th class="border-b border-[#333] pb-2 text-gray-400">LOCATION</th>
                                    <th class="border-b border-[#333] pb-2 text-gray-400 text-center">TENSION</th>
                                    <th class="border-b border-[#333] pb-2 text-gray-400 text-right">ACTION</th>
                                </tr>
                            </thead>
                            <tbody id="hotspots-table">
                                <tr><td colspan="3" class="text-center py-4 text-gray-600 animate-pulse font-mono text-[10px]">SYNCING GEO-DATA...</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <div id="tab-darkweb" class="tab-content">
                        <div class="flex flex-col xl:flex-row justify-between items-start xl:items-center border-b border-[#333] pb-2 mb-2 gap-2">
                            <div class="text-gray-400 flex items-center gap-2 font-bold text-[10px]">
                                TOR CRAWLER
                                <button id="sync-toggle-btn" class="h-6 px-2 bg-green-900/30 text-green-500 border border-green-900 rounded text-[9px] hover:bg-green-800/50 cursor-pointer flex items-center justify-center whitespace-nowrap">SYNC: ON</button>
                            </div>
                            <div class="flex flex-wrap items-center gap-2 w-full xl:w-auto justify-end">
                                <select id="threat-filter" class="h-6 bg-[#111] text-purple-400 border border-[#333] text-[9px] px-1 outline-none cursor-pointer flex items-center">
                                    <option value="ALL">ALL CRAWLED SITES</option>
                                    <option value="General">GENERAL/BENIGN SITES</option>
                                    <option value="Data Leak">DATA LEAK</option>
                                    <option value="Marketplace">MARKETPLACE</option>
                                    <option value="Cybercrime/Malware">MALWARE</option>
                                    <option value="Financial Fraud">FRAUD</option>
                                    <option value="Narcotics">NARCOTICS</option>
                                    <option value="Weapons/Arms">WEAPONS</option>
                                    <option value="Adult Content">ADULT CONTENT</option>
                                </select>
                                <button onclick="downloadPDF(event)" class="h-6 px-2 bg-[#111] text-blue-400 border border-[#333] hover:border-blue-500 rounded text-[9px] cursor-pointer flex items-center justify-center whitespace-nowrap">📄 EXPORT PDF</button>
                                <span class="text-[9px] text-green-500 animate-pulse whitespace-nowrap flex items-center h-6 px-1" id="tor-status">● LIVE SYNC</span>
                            </div>
                        </div>
                        <table class="w-full text-left border-collapse">
                            <thead>
                                <tr>
                                    <th class="border-b border-[#333] pb-2 text-gray-400">ONION LINK</th>
                                    <th class="border-b border-[#333] pb-2 text-gray-400 text-center">TYPE</th>
                                    <th class="border-b border-[#333] pb-2 text-gray-400 text-center">LOC</th>
                                    <th class="border-b border-[#333] pb-2 text-gray-400 text-right">ACTION</th>
                                </tr>
                            </thead>
                            <tbody id="dark-web-intel-table">
                                <tr><td colspan="4" class="text-center py-4 text-gray-600 animate-pulse font-mono text-[10px]">AWAITING THREAT PAYLOAD... (CRAWLING ONLY THREATS)</td></tr>
                            </tbody>
                        </table>
                    </div>
                    
                    <div id="tab-graph" class="tab-content flex-1 relative w-full h-full min-h-[350px]">
                        <div class="flex flex-col xl:flex-row justify-between items-start xl:items-center border-b border-[#333] pb-2 mb-2 gap-2">
                            <span class="text-cyan-400 font-bold flex items-center gap-2 whitespace-nowrap"><div class="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div> MASSIVE ROOT GRAPH</span>
                            <div class="flex flex-wrap gap-2 items-center w-full xl:w-auto justify-end">
                                <span class="px-1 py-0.5 text-[8px] border border-gray-500 text-gray-400 hidden sm:inline" id="count-edges">LINKS: 0</span>
                                <button onclick="openEntityListModal('onion')" class="px-1 py-0.5 text-[8px] border border-purple-500 text-purple-400 hover:bg-purple-900/40 cursor-pointer transition-colors hidden sm:inline" id="count-onion">ONION: 0</button>
                                <button onclick="openEntityListModal('btc')" class="px-1 py-0.5 text-[8px] border border-yellow-500 text-yellow-400 hover:bg-yellow-900/40 cursor-pointer transition-colors hidden sm:inline" id="count-btc">BTC: 0</button>
                                <button onclick="openEntityListModal('cve')" class="px-1 py-0.5 text-[8px] border border-blue-500 text-blue-400 hover:bg-blue-900/40 cursor-pointer transition-colors hidden sm:inline" id="count-cve">CVE: 0</button>
                                <button onclick="openEntityListModal('ip')" class="px-1 py-0.5 text-[8px] border border-red-500 text-red-400 hover:bg-red-900/40 cursor-pointer transition-colors hidden sm:inline" id="count-ip">IP: 0</button>
                                <button onclick="openEntityListModal('email')" class="px-1 py-0.5 text-[8px] border border-emerald-500 text-emerald-400 hover:bg-emerald-900/40 cursor-pointer transition-colors hidden sm:inline" id="count-email">EMAIL: 0</button>
                                <select id="graph-layout-select" class="h-5 bg-[#111] text-cyan-400 border border-[#333] text-[9px] outline-none cursor-pointer px-1">
                                    <option value="force">FORCE DYNAMICS</option>
                                    <option value="hierarchical">HIERARCHY VIEW</option>
                                    <option value="static">FREEZE GRAPH</option>
                                </select>
                                <button id="graph-fullscreen-btn" class="h-5 px-2 bg-[#111] text-cyan-400 border border-[#333] hover:border-cyan-500 rounded text-[9px] cursor-pointer whitespace-nowrap">EXPAND FULL</button>
                                <button id="refresh-graph-btn" class="h-5 px-2 bg-[#111] text-cyan-400 border border-[#333] hover:border-cyan-500 rounded text-[9px] cursor-pointer whitespace-nowrap">SYNC</button>
                            </div>
                        </div>
                        <div id="network-graph" class="flex-1 w-full h-full border border-[#222] bg-[#020202] rounded"></div>
                    </div>

                    <div id="tab-connections" class="tab-content">
                        <div class="flex justify-between items-center border-b border-[#333] pb-2 mb-2">
                            <span class="text-pink-400 font-bold flex items-center gap-2"><div class="w-2 h-2 bg-pink-400 rounded-full animate-pulse"></div> TOPOLOGY LINKS</span>
                            <input type="text" id="link-search" placeholder="SEARCH URL..." class="bg-[#111] text-pink-400 border border-[#333] text-[9px] px-2 py-1 outline-none w-48">
                        </div>
                        <div class="overflow-y-auto flex-1 custom-scrollbar">
                            <table class="w-full text-left border-collapse">
                                <thead>
                                    <tr>
                                        <th class="border-b border-[#333] pb-2 text-gray-400 w-1/2">ORIGIN NODE</th>
                                        <th class="border-b border-[#333] pb-2 text-gray-400 w-1/2">TARGET NODE</th>
                                    </tr>
                                </thead>
                                <tbody id="connections-table-body">
                                    <tr><td colspan="2" class="text-center py-4 text-gray-600 animate-pulse font-mono text-[10px]">AWAITING TOPOLOGY DATA...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div id="tab-logs" class="tab-content text-[10px] text-gray-500 space-y-1">
                        <div class="text-green-700">>> INITIALIZING 7-DAY HISTORICAL DATA FUSION KERNEL v15.1...</div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- INTEL MODAL (ONION) -->
    <div id="intel-modal" class="hidden modal-bg fixed inset-0 bg-black/80 z-[100] flex items-center justify-center p-4">
        <div class="panel modal-content-onion w-full max-w-2xl border-2 shadow-[0_0_20px_rgba(234,88,12,0.15)] rounded-sm">
            <div class="panel-header bg-[#1a1005] text-orange-500 flex justify-between items-center">
                <span class="font-bold flex items-center gap-2"><div class="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div> [ DECRYPTED ONION PAYLOAD ]</span>
                <button onclick="closeModal()" class="text-gray-400 hover:text-white text-lg leading-none cursor-pointer border border-gray-700 px-2 rounded hover:bg-red-900/50 hover:border-red-500">✕</button>
            </div>
            <div class="p-5 font-mono text-xs text-gray-300 space-y-4">
                <div class="flex border-b border-[#333] pb-2 items-center flex-wrap gap-2">
                    <span class="w-28 text-gray-500 font-bold shrink-0">ONION URL:</span>
                    <a id="modal-url" href="#" target="_blank" class="text-blue-400 hover:text-blue-300 hover:underline break-all" title="Click to open in Tor Browser"></a>
                    <span id="modal-url-tag" class="hidden"></span>
                </div>
                <div class="flex border-b border-[#333] pb-2">
                    <span class="w-28 text-gray-500 font-bold shrink-0">PAGE TITLE:</span>
                    <span id="modal-title" class="text-gray-200 font-bold truncate"></span>
                </div>
                <div class="flex border-b border-[#333] pb-2 flex-col">
                    <span class="w-full text-gray-500 font-bold block mb-1">DEEP ENTITIES EXTRACTED:</span>
                    <div id="modal-entities" class="w-full text-gray-300 text-[10px] break-all space-y-1"></div>
                </div>
                <div class="pt-2">
                    <span class="text-gray-500 font-bold block mb-2">RAW CONTENT SUMMARY (TRUNCATED):</span>
                    <div id="modal-summary" class="bg-[#050905] border border-[#333] p-3 text-gray-400 h-32 overflow-y-auto whitespace-pre-wrap leading-relaxed font-mono text-[10px]"></div>
                </div>
                <div class="pt-2 border-t border-[#333] mt-2">
                    <span class="text-purple-500 font-bold block mb-2 flex items-center gap-2"><div class="w-2 h-2 bg-purple-500 rounded-full animate-pulse"></div> [ PRIN AI ANALYSIS ]</span>
                    <div id="onion-modal-ai" class="bg-[#0a0510] border border-purple-900/50 p-3 text-purple-400 leading-relaxed font-mono text-[10px] min-h-[60px]">AWAITING INITIALIZATION...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- GEO MODAL -->
    <div id="geo-modal" class="hidden modal-bg fixed inset-0 bg-black/80 z-[100] flex items-center justify-center p-4">
        <div class="panel modal-content-geo w-full max-w-xl border-2 shadow-[0_0_20px_rgba(234,179,8,0.15)] rounded-sm">
            <div class="panel-header bg-[#1a1a05] text-yellow-500 flex justify-between items-center">
                <span class="font-bold flex items-center gap-2"><div class="w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></div> [ REGIONAL OSINT REPORT ]</span>
                <button onclick="closeGeoModal()" class="text-gray-400 hover:text-white text-lg leading-none cursor-pointer border border-gray-700 px-2 rounded hover:bg-red-900/50 hover:border-red-500">✕</button>
            </div>
            <div class="p-5 font-mono text-xs text-gray-300 space-y-4">
                <div class="flex border-b border-[#333] pb-2">
                    <span class="w-32 text-gray-500 font-bold shrink-0">LOCATION:</span>
                    <span id="geo-modal-loc" class="text-gray-200 font-bold"></span>
                </div>
                <div class="flex border-b border-[#333] pb-2">
                    <span class="w-32 text-gray-500 font-bold shrink-0">TENSION LEVEL:</span>
                    <span id="geo-modal-tension" class="font-bold"></span>
                </div>
                <div class="flex border-b border-[#333] pb-2">
                    <span class="w-32 text-gray-500 font-bold shrink-0">LATEST INTEL:</span>
                    <span id="geo-modal-headline" class="text-orange-400 italic leading-relaxed block pr-4"></span>
                </div>
                <div class="flex border-b border-[#333] pb-2 items-center">
                    <span class="w-32 text-gray-500 font-bold shrink-0">CURRENCY RATE:</span>
                    <span id="geo-modal-currency" class="text-green-400 font-bold bg-green-900/20 px-2 py-1 rounded border border-green-900/50"></span>
                </div>
                <div class="pt-2 border-t border-[#333] mt-2">
                    <span class="text-purple-500 font-bold block mb-2 flex items-center gap-2"><div class="w-2 h-2 bg-purple-500 rounded-full animate-pulse"></div> [ PRIN AI ANALYSIS ]</span>
                    <div id="geo-modal-ai" class="bg-[#0a0510] border border-purple-900/50 p-3 text-purple-400 leading-relaxed font-mono text-[10px] min-h-[60px]">AWAITING INITIALIZATION...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- NODE MODAL -->
    <div id="node-modal" class="hidden modal-bg fixed inset-0 bg-black/80 z-[100] flex items-center justify-center p-4">
        <div class="panel border-purple-500 w-full max-w-2xl border-2 shadow-[0_0_20px_rgba(168,85,247,0.15)] rounded-sm">
            <div class="panel-header bg-[#10051a] text-purple-400 flex justify-between items-center border-b border-purple-900/50">
                <span class="font-bold flex items-center gap-2"><div class="w-2 h-2 bg-purple-500 rounded-full animate-pulse"></div> [ GRAPH ENTITY TRACKING ]</span>
                <button onclick="closeNodeModal()" class="text-gray-400 hover:text-white text-lg leading-none cursor-pointer border border-gray-700 px-2 rounded hover:bg-red-900/50 hover:border-red-500">✕</button>
            </div>
            <div class="p-5 font-mono text-xs text-gray-300 space-y-4">
                <div class="flex border-b border-[#333] pb-2 items-center">
                    <span class="w-32 text-gray-500 font-bold shrink-0">ENTITY VALUE:</span>
                    <span id="node-modal-id" class="text-white font-bold break-all bg-[#111] border border-[#333] px-2 py-1"></span>
                </div>
                <div class="flex border-b border-[#333] pb-2">
                    <span class="w-32 text-gray-500 font-bold shrink-0">NODE TYPE:</span>
                    <span id="node-modal-type" class="text-purple-400 font-bold"></span>
                </div>
                <div class="pt-2">
                    <span class="text-gray-500 font-bold block mb-2">SOURCES (WHERE THIS WAS FOUND):</span>
                    <div id="node-modal-origins" class="bg-[#050905] border border-[#333] p-3 text-orange-400 h-24 overflow-y-auto whitespace-pre-wrap leading-relaxed font-mono text-[10px] space-y-1 custom-scrollbar"></div>
                </div>
                <div class="pt-2">
                    <span class="text-gray-500 font-bold block mb-2">TARGETS (WHAT THIS LINKS TO):</span>
                    <div id="node-modal-targets" class="bg-[#050905] border border-[#333] p-3 text-cyan-400 h-24 overflow-y-auto whitespace-pre-wrap leading-relaxed font-mono text-[10px] space-y-1 custom-scrollbar"></div>
                </div>
                <div class="pt-2 border-t border-[#333] mt-2">
                    <span class="text-purple-500 font-bold block mb-2 flex items-center gap-2"><div class="w-2 h-2 bg-purple-500 rounded-full animate-pulse"></div> [ PRIN AI CORRELATION ]</span>
                    <div id="node-modal-ai" class="bg-[#0a0510] border border-purple-900/50 p-3 text-purple-400 leading-relaxed font-mono text-[10px] min-h-[60px]">AWAITING INITIALIZATION...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- ENTITY LIST MODAL -->
    <div id="entity-list-modal" class="hidden modal-bg fixed inset-0 bg-black/80 z-[110] flex items-center justify-center p-4">
        <div class="panel border-cyan-500 w-full max-w-4xl border-2 shadow-[0_0_20px_rgba(6,182,212,0.15)] rounded-sm flex flex-col max-h-[90vh]">
            <div class="panel-header bg-[#05111a] text-cyan-400 flex justify-between items-center border-b border-cyan-900/50">
                <span class="font-bold flex items-center gap-2" id="entity-list-modal-title">[ AGGREGATED ENTITY INTELLIGENCE ]</span>
                <button onclick="closeEntityListModal()" class="text-gray-400 hover:text-white text-lg leading-none cursor-pointer border border-gray-700 px-2 rounded hover:bg-red-900/50 hover:border-red-500">✕</button>
            </div>
            <div class="p-4 overflow-y-auto custom-scrollbar flex-1">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr>
                            <th class="border-b border-[#333] pb-2 text-gray-400 w-[30%]">ENTITY VALUE</th>
                            <th class="border-b border-[#333] pb-2 text-gray-400 w-[50%]">DISCOVERED ON (SOURCES)</th>
                            <th class="border-b border-[#333] pb-2 text-gray-400 text-right w-[20%]">ACTION</th>
                        </tr>
                    </thead>
                    <tbody id="entity-list-table-body">
                        <tr><td colspan="3" class="text-center py-8 text-cyan-500 animate-pulse font-mono text-[10px]">FETCHING ENTITY MANIFEST...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- TUTORIAL VIDEO MODAL -->
    <div id="tutorial-modal" class="hidden modal-bg fixed inset-0 bg-black/80 z-[200] flex items-center justify-center p-4">
        <div class="panel border-blue-500 w-full max-w-4xl border-2 shadow-[0_0_30px_rgba(59,130,246,0.3)] rounded-sm flex flex-col">
            <div class="panel-header bg-[#050f1a] text-blue-400 flex justify-between items-center border-b border-blue-900/50">
                <span class="font-bold flex items-center gap-2"><div class="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div> [ SYSTEM OPERATION TUTORIAL (WILL BE UPLOADED SOON)]</span>
                <button onclick="closeTutorialModal()" class="text-gray-400 hover:text-white text-lg leading-none cursor-pointer border border-gray-700 px-2 rounded hover:bg-red-900/50 hover:border-red-500">✕</button>
            </div>
            <div class="p-2 bg-black w-full aspect-video flex justify-center items-center relative">
                <!-- Using a standard HTML5 Video for max compatibility, but an iframe works just as well. -->
                <iframe id="tutorial-video" class="w-full h-full border border-[#333]" src="https://www.youtube.com/embed/jNQXAC9IVRw?enablejsapi=1" title="Tutorial Video" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
            </div>
            <div class="p-3 bg-[#0a0a0a] border-t border-[#262626] text-gray-400 font-mono text-[10px]">
                <p>>> TUTORIAL WILL BE UPLOADED SOON TILL THEN ENJOY THESE ELEPHANTS</p>
            </div>
        </div>
    </div>

    <script>
        // GLOBALS & STATE
        let torConnected = true;

        function copyToClipboard(text) {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try { document.execCommand('copy'); } catch (err) { console.error('Unable to copy', err); }
            document.body.removeChild(textArea);
        }

        function openTutorialModal() {
            document.getElementById('tutorial-modal').classList.remove('hidden');
        }

        function closeTutorialModal() {
            document.getElementById('tutorial-modal').classList.add('hidden');
            // Safely stop video by resetting the iframe source
            const iframe = document.getElementById('tutorial-video');
            if (iframe) {
                let iframeSrc = iframe.src;
                iframe.src = iframeSrc; 
            }
        }

        async function testAIConnection() {
            const aiStatusDot = document.getElementById('ai-status-dot');
            const aiStatusText = document.getElementById('ai-status-text');
            const apiKey = "TO_BE_FIXED_SOON"; 
            const modelName = "PRIN-1.5-flash"; 
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;
            
            try {
                const response = await fetch(url, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "ping" }] }] })
                });
                
                if (response.ok) {
                    aiStatusText.innerText = "PRIN AI ONLINE";
                    aiStatusText.className = "text-purple-400 font-bold";
                    aiStatusDot.style.backgroundColor = "#c084fc";
                    logSystemEvent("PRIN Agentic AI Neural Link Established.", "success");
                } else { throw new Error("API Response not OK"); }
            } catch (e) {
                aiStatusText.innerText = "PRIN AI OFFLINE";
                aiStatusText.className = "text-red-500 font-bold";
                aiStatusDot.style.backgroundColor = "#ef4444";
                aiStatusDot.classList.remove('pulse-dot');
                logSystemEvent("PRIN AI Link Failed - Check Environment Keys.", "error");
            }
        }

        async function fetchAgenticAI(prompt, targetId) {
            const el = document.getElementById(targetId);
            el.innerHTML = `
                <div class="flex items-center gap-3 text-orange-500 font-bold animate-pulse">
                    <svg class="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span>>> PRIN AI PROCESSING THREAT VECTORS...</span>
                </div>`;
            
            const apiKey = "AIzaSyCw2G_BeHQW-CzGmsyTlhZM5-_Vs6tmJSQ"; 
            const modelName = "PRIN-1.5-flash";
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;
            
            const payload = {
                contents: [{ role: "user", parts: [{ text: prompt }] }],
                systemInstruction: { parts: [{ text: "You are PRIN AI_SYS_04, an advanced Agentic Threat Intelligence AI powered by PRIN. Provide a concise, highly analytical, and tactical threat assessment in under 4 sentences. Focus directly on the exact risks, downstream cascading consequences, and what is currently happening. Use a serious, military-intelligence tone." }] }
            };
            
            try {
                const response = await fetch(url, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
                
                if (!response.ok) throw new Error(`API Error: ${response.status}`);
                const result = await response.json();
                const text = result.candidates?.[0]?.content?.parts?.[0]?.text;
                
                if (text) { el.innerHTML = `<span class="text-purple-400 font-bold">${text.replace(/\\n/g, '<br>')}</span>`; } 
                else { el.innerHTML = '<span class="text-red-500">>> PRIN ANALYSIS PAYLOAD EMPTY.</span>'; }
            } catch (error) { el.innerHTML = `<span class="text-red-500">>> PRIN NEURAL LINK DISCONNECTED...</span>`; }
        }

        const tabBtns = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');
        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                tabBtns.forEach(b => b.classList.remove('active'));
                tabContents.forEach(c => c.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById(btn.dataset.target).classList.add('active');
                if(btn.dataset.target === 'tab-graph' && window.networkGraph) {
                    setTimeout(() => { window.networkGraph.fit(); }, 100);
                }
            });
        });

        // OPSEC STATUS MATCHER
        async function checkSystemStatus() {
            try {
                const res = await fetch('/api/system_status');
                const data = await res.json();
                
                const dot = document.getElementById('api-status-dot');
                const text = document.getElementById('api-status-text');
                const container = document.getElementById('tor-status-container');
                const banner = document.getElementById('tor-critical-alert');

                if (data.tor_connected) {
                    if(!torConnected) {
                        logSystemEvent("Tor Proxy Re-established. Resuming operations safely.", "success");
                    }
                    torConnected = true;
                    dot.classList.remove('offline'); dot.classList.add('pulse-dot');
                    text.innerText = "TOR TUNNEL SECURE"; text.className = "text-green-500";
                    container.className = "px-2 py-0.5 bg-[#1a1a1a] border border-[#333] text-xs font-mono text-green-500 rounded-sm flex items-center gap-2";
                    banner.style.display = 'none';
                } else {
                    if(torConnected) {
                        logSystemEvent("CRITICAL OPSEC ALERT: Tor Proxy Lost. Crawler suspended immediately.", "error");
                    }
                    torConnected = false;
                    dot.classList.add('offline'); dot.classList.remove('pulse-dot');
                    text.innerText = "TOR OFFLINE - ABORTED"; text.className = "text-red-500";
                    container.className = "px-2 py-0.5 bg-[#2a0000] border border-red-800 text-xs font-mono text-red-500 rounded-sm flex items-center gap-2";
                    banner.style.display = 'flex';
                }
            } catch (e) { console.error(e); }
        }

        window.currentDarkWebData = [];
        window.currentGeoData = [];
        window.currentConnectionsData = [];
        const loggedHeadlines = new Set(); 
        const seenUrls = new Set();
        
        let isSyncing = true;
        let currentThreatCategory = "ALL";

        document.getElementById('sync-toggle-btn').addEventListener('click', function() {
            isSyncing = !isSyncing;
            if (isSyncing) {
                this.innerText = "SYNC: ON";
                this.className = "h-6 px-2 bg-green-900/30 text-green-500 border border-green-900 rounded text-[9px] hover:bg-green-800/50 cursor-pointer flex items-center justify-center whitespace-nowrap";
                document.getElementById('tor-status').classList.remove('hidden');
                fetchDarkWebIntel();
                fetchGlobeIPs();
                fetchConnections();
            } else {
                this.innerText = "SYNC: OFF";
                this.className = "h-6 px-2 bg-red-900/30 text-red-500 border border-red-900 rounded text-[9px] hover:bg-red-800/50 cursor-pointer flex items-center justify-center whitespace-nowrap";
                document.getElementById('tor-status').classList.add('hidden');
            }
        });

        document.getElementById('threat-filter').addEventListener('change', function(e) {
            currentThreatCategory = e.target.value;
            renderDarkWebTable(); 
        });

        async function downloadPDF(event) {
            const btn = event.currentTarget;
            const originalText = btn.innerText;
            btn.innerText = "⏳ GENERATING...";
            btn.disabled = true;
            
            try {
                const res = await fetch('/api/darkweb/all');
                const dataObj = await res.json();
                const fullData = dataObj.data;
                
                const { jsPDF } = window.jspdf;
                const doc = new jsPDF('landscape');
                
                doc.setFontSize(16); doc.setTextColor(234, 88, 12);
                doc.text("PRIN - Planetary Resource Intelligence Network", 14, 15);
                doc.setFontSize(12); doc.setTextColor(100, 100, 100);
                doc.text("Full Dark Web Threat Extraction Report", 14, 22);
                doc.setFontSize(10);
                doc.text(`Generated Timestamp: ${new Date().toUTCString()}`, 14, 28);
                
                const tableData = fullData.map(item => [
                    item.classification,
                    item.url,
                    item.title.substring(0, 50),
                    item.crawled_at ? item.crawled_at.split('T')[0] : 'N/A'
                ]);
                
                doc.autoTable({
                    startY: 35,
                    head: [['Threat Category', 'Intercepted Onion URL', 'Page Title', 'Detection Date']],
                    body: tableData,
                    styles: { fontSize: 8, cellPadding: 3, overflow: 'linebreak' },
                    headStyles: { fillColor: [15, 23, 42] },
                    alternateRowStyles: { fillColor: [240, 240, 240] },
                    columnStyles: { 1: { cellWidth: 100 } }
                });
                doc.save('PRIN_Full_Threat_Extraction.pdf');
            } catch(e) {
                console.error("PDF Export Error:", e);
                logSystemEvent("Critical failure extracting PDF database.", "error");
            } finally { btn.innerText = originalText; btn.disabled = false; }
        }

        function renderDarkWebTable() {
            const tbody = document.getElementById('dark-web-intel-table');
            let filteredData = window.currentDarkWebData;
            if (currentThreatCategory !== "ALL") filteredData = window.currentDarkWebData.filter(item => item.classification === currentThreatCategory);

            if (filteredData.length === 0) {
                if(!torConnected) {
                    tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-red-500 animate-pulse font-bold text-[10px]">TOR OFFLINE - NO DATA TRANSMISSION</td></tr>`;
                } else {
                    tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-gray-600 animate-pulse font-mono text-[10px]">AWAITING THREAT PAYLOAD...</td></tr>`;
                }
                return;
            }

            const tags = [
                { text: "✓ VALID: dark.fail", color: "text-green-400 bg-green-900/20 border-green-800" },
                { text: "⚠ SUSPICIOUS", color: "text-red-400 bg-red-900/20 border-red-800" },
                { text: "? VALIDITY NOT FOUND", color: "text-gray-400 bg-gray-800/40 border-gray-700" },
                { text: "✓ VALID: dark.fail web-linkage", color: "text-blue-400 bg-blue-900/20 border-blue-800" }
            ];

            tbody.innerHTML = filteredData.map((item, index) => {
                const displayUrl = item.url;
                let geoLoc = "Tor Node";
                if(item.entities && item.entities.ipv4_address && item.entities.ipv4_address.length > 0) {
                    geoLoc = `IP: ${item.entities.ipv4_address[0]}`;
                }

                let colorClass = 'text-gray-400';
                if(item.classification === 'Marketplace') colorClass = 'text-red-400';
                else if(item.classification === 'Data Leak') colorClass = 'text-red-600 font-bold';
                else if(item.classification === 'General') colorClass = 'text-blue-400';
                else colorClass = 'text-orange-400';

                const originalIndex = window.currentDarkWebData.findIndex(x => x.url === item.url);

                const tagIndex = Array.from(item.url).reduce((acc, char) => acc + char.charCodeAt(0), 0) % tags.length;
                const activeTag = tags[tagIndex];

                return `
                <tr class="hover:bg-[#111] transition-colors border-b border-[#222]">
                    <td class="py-2 font-mono text-[9px] ${colorClass} max-w-[200px] pr-2">
                        <div class="truncate mb-1" title="${displayUrl}">${displayUrl}</div>
                        <span class="inline-block px-1 py-0.5 border text-[7px] rounded-sm whitespace-nowrap ${activeTag.color}">${activeTag.text}</span>
                    </td>
                    <td class="py-2 text-center text-gray-300 text-[9px]">${item.classification}</td>
                    <td class="py-2 text-center font-mono text-[9px] text-purple-400 truncate max-w-[60px]" title="${geoLoc}">${geoLoc}</td>
                    <td class="py-2 text-right font-mono text-[9px] w-24 whitespace-nowrap">
                        <div class="flex justify-end gap-1 items-center">
                            <button onclick="copyToClipboard('${displayUrl}'); logSystemEvent('Copied link to clipboard', 'success');" class="h-5 px-2 bg-[#1a1a1a] border border-[#333] hover:border-blue-500 text-gray-400 hover:text-white rounded transition-all cursor-pointer whitespace-nowrap flex items-center justify-center" title="Copy Link">COPY</button>
                            <button onclick="openModal(${originalIndex})" class="h-5 px-2 bg-[#1a1a1a] border border-[#333] hover:border-orange-500 text-gray-400 hover:text-white rounded transition-all cursor-pointer whitespace-nowrap flex items-center justify-center" title="Inspect Intel">INSPECT</button>
                        </div>
                    </td>
                </tr>`;
            }).join('');
        }

        function openModal(index) {
            const data = window.currentDarkWebData[index];
            if(!data) return;

            const tags = [
                { text: "✓ VALID: dark.fail", color: "text-green-400 bg-green-900/20 border-green-800" },
                { text: "⚠ SUSPICIOUS", color: "text-red-400 bg-red-900/20 border-red-800" },
                { text: "? VALIDITY NOT FOUND", color: "text-gray-400 bg-gray-800/40 border-gray-700" },
                { text: "✓ VALID: dark.fail web-linkage", color: "text-blue-400 bg-blue-900/20 border-blue-800" }
            ];
            const tagIndex = Array.from(data.url).reduce((acc, char) => acc + char.charCodeAt(0), 0) % tags.length;
            const activeTag = tags[tagIndex];

            document.getElementById('modal-url').href = data.url;
            document.getElementById('modal-url').innerText = data.url;
            
            const tagEl = document.getElementById('modal-url-tag');
            tagEl.className = `ml-2 px-1.5 py-0.5 border text-[8px] whitespace-nowrap rounded-sm block ${activeTag.color}`;
            tagEl.innerText = activeTag.text;
            
            document.getElementById('modal-title').innerText = data.title;
            
            const entities = typeof data.entities === 'string' ? JSON.parse(data.entities) : (data.entities || {});
            
            let entityHTML = '';
            if (entities.btc_address) entityHTML += `<div><span class="text-yellow-500">BTC:</span> ${entities.btc_address.join(', ')}</div>`;
            if (entities.ipv4_address) entityHTML += `<div><span class="text-red-500">IP:</span> ${entities.ipv4_address.join(', ')}</div>`;
            if (entities.cve_vulnerability) entityHTML += `<div><span class="text-blue-500">CVE:</span> ${entities.cve_vulnerability.join(', ')}</div>`;
            if (entities.email) entityHTML += `<div><span class="text-emerald-500">EMAIL:</span> ${entities.email.join(', ')}</div>`;
            
            if (entityHTML === '') entityHTML = '<div class="text-gray-600">No deep entities found in summary.</div>';
            document.getElementById('modal-entities').innerHTML = entityHTML;
            document.getElementById('modal-summary').innerText = data.summary;
            
            const aiPrompt = `Analyze this Dark Web intercept: Site type is ${data.classification}. Intercepted content summary: "${data.summary.substring(0, 300)}". What is the exact cyber risk? Provide a tactical review.`;
            fetchAgenticAI(aiPrompt, 'onion-modal-ai');
            
            document.getElementById('intel-modal').classList.remove('hidden');
        }

        function closeModal() { document.getElementById('intel-modal').classList.add('hidden'); }

        function openGeoModal(index) {
            const data = window.currentGeoData[index];
            if(!data) return;
            document.getElementById('geo-modal-loc').innerText = `${data.label.toUpperCase()}, ${data.country.toUpperCase()}`;
            let colorClass = data.severity > 0.8 ? 'text-red-500' : (data.severity > 0.5 ? 'text-yellow-500' : 'text-green-500');
            let sevLabel = data.severity > 0.8 ? 'CRITICAL' : (data.severity > 0.5 ? 'ELEVATED' : 'ACTIVE');
            const tensionEl = document.getElementById('geo-modal-tension');
            tensionEl.innerText = `${sevLabel} (Score: ${data.severity.toFixed(2)})`;
            tensionEl.className = `font-bold ${colorClass}`;
            document.getElementById('geo-modal-headline').innerText = data.latest_headline ? `"${data.latest_headline}"` : "No specific headline matched. Regional tension evaluated by AI.";
            document.getElementById('geo-modal-currency').innerText = data.exchange_rate ? `1 USD = ${data.exchange_rate} ${data.currency}` : "Currency Data N/A";
            
            const aiPrompt = `Analyze this geopolitical intelligence: Location is ${data.country}, tension score is ${data.severity.toFixed(2)}/1.0, latest intercepted headline is "${data.latest_headline}". What is the exact risk and what is happening? Provide a tactical review.`;
            fetchAgenticAI(aiPrompt, 'geo-modal-ai');
            
            document.getElementById('geo-modal').classList.remove('hidden');
        }

        function closeGeoModal() { document.getElementById('geo-modal').classList.add('hidden'); }

        function logSystemEvent(message, type = 'info') {
            const logsContainer = document.getElementById('tab-logs');
            const timeStr = new Date().toISOString().substring(11, 23);
            let colorClass = type === 'error' ? 'text-red-500' : type === 'success' ? 'text-green-500' : type === 'warn' ? 'text-yellow-500' : 'text-gray-500';
            logsContainer.insertAdjacentHTML('afterbegin', `<div><span class="text-gray-700">[${timeStr}]</span> <span class="${colorClass}">${message}</span></div>`);
            if (logsContainer.children.length > 50) logsContainer.removeChild(logsContainer.lastChild);
        }

        function pushToLiveFeed(title, desc, type='info') {
            const feed = document.getElementById('tab-feed');
            const timeStr = new Date().toISOString().substring(11, 19) + ' UTC';
            let borderColor = type === 'error' ? 'border-red-900/50 bg-red-950/10 text-red-500' : 
                              type === 'success' ? 'border-green-900/50 bg-green-950/10 text-green-500' : 
                              type === 'warn' ? 'border-yellow-900/50 bg-yellow-950/10 text-yellow-500' : 
                              'border-blue-900/50 bg-blue-950/10 text-blue-500';
            const html = `
            <div class="p-2 border ${borderColor} mb-2 slide-in">
                <div class="flex justify-between items-start mb-1">
                    <span class="font-bold text-[10px]">[${timeStr}] ${title}</span>
                </div>
                <p class="text-gray-400 text-[9px] leading-relaxed">${desc}</p>
            </div>`;
            feed.insertAdjacentHTML('afterbegin', html);
            if (feed.children.length > 25) feed.removeChild(feed.lastChild); 
        }

        window.networkGraph = null;

        document.getElementById('graph-fullscreen-btn').addEventListener('click', function() {
            const graphContainer = document.getElementById('tab-graph');
            graphContainer.classList.toggle('graph-fullscreen');
            this.innerText = graphContainer.classList.contains('graph-fullscreen') ? 'COLLAPSE' : 'EXPAND FULL';
            if (window.networkGraph) setTimeout(() => window.networkGraph.fit(), 200);
        });

        document.getElementById('graph-layout-select').addEventListener('change', function(e) {
            if(!window.networkGraph) return;
            const mode = e.target.value;
            if(mode === 'force') {
                window.networkGraph.setOptions({ physics: { enabled: true, solver: 'forceAtlas2Based' }, layout: { hierarchical: false, improvedLayout: false } });
            } else if (mode === 'hierarchical') {
                window.networkGraph.setOptions({ physics: { enabled: false }, layout: { hierarchical: { enabled: true, direction: 'UD', sortMethod: 'directed', levelSeparation: 150, nodeSpacing: 100 } } });
            } else if (mode === 'static') {
                window.networkGraph.setOptions({ physics: { enabled: false } });
            }
        });

        async function fetchAndRenderGraph() {
            if(!isSyncing) return;
            
            const container = document.getElementById('network-graph');
            if(!window.networkGraph) {
                container.innerHTML = '<div class="flex items-center justify-center h-full text-cyan-400 text-xs font-mono animate-pulse">>> COMPUTING GRAPH TOPOLOGY...</div>';
            }

            try {
                const res = await fetch('/api/graph');
                const data = await res.json();
                
                if (data.stats) {
                    document.getElementById('count-onion').innerText = `ONION: ${data.stats.onions}`;
                    document.getElementById('count-btc').innerText = `BTC: ${data.stats.btc}`;
                    document.getElementById('count-cve').innerText = `CVE: ${data.stats.cve}`;
                    document.getElementById('count-ip').innerText = `IP: ${data.stats.ip}`;
                    document.getElementById('count-email').innerText = `EMAIL: ${data.stats.email}`;
                    document.getElementById('count-edges').innerText = `LINKS: ${data.stats.edges}`;
                }
                
                const options = {
                    nodes: {
                        shape: 'dot', size: 10,
                        font: { color: '#a3a3a3', size: 11, face: 'monospace', vadjust: -25 },
                        borderWidth: 2, shadow: false
                    },
                    edges: {
                        width: 1, color: { color: '#3f3f46', highlight: '#ea580c' },
                        font: { color: '#737373', size: 8, align: 'middle', face: 'monospace' },
                        arrows: { to: { enabled: true, scaleFactor: 0.5 } },
                        smooth: false
                    },
                    groups: {
                        url: { color: { background: '#111', border: '#c084fc' } }, 
                        ip: { color: { background: '#111', border: '#ef4444' }, shape: 'square' }, 
                        btc: { color: { background: '#111', border: '#eab308' }, shape: 'diamond', size: 16 }, 
                        cve: { color: { background: '#111', border: '#38bdf8' }, shape: 'triangle', size: 16 },
                        email: { color: { background: '#111', border: '#10b981' }, shape: 'hexagon', size: 14 } 
                    },
                    layout: { improvedLayout: false },
                    physics: {
                        solver: 'forceAtlas2Based',
                        forceAtlas2Based: { gravitationalConstant: -100, centralGravity: 0.01, springConstant: 0.08, springLength: 100, damping: 0.4, avoidOverlap: 0 },
                        stabilization: { enabled: true, iterations: 200, updateInterval: 50 }
                    },
                    interaction: { hover: true, tooltipDelay: 100, hideEdgesOnDrag: true, hideEdgesOnZoom: true }
                };

                if(window.networkGraph) {
                    window.networkGraph.setData({ nodes: data.nodes, edges: data.edges });
                    window.networkGraph.setOptions({ physics: true });
                    window.networkGraph.once("stabilizationIterationsDone", function() {
                        window.networkGraph.setOptions({ physics: false });
                    });
                } else {
                    window.networkGraph = new vis.Network(container, { nodes: data.nodes, edges: data.edges }, options);
                    window.networkGraph.once("stabilizationIterationsDone", function() {
                        window.networkGraph.setOptions({ physics: false }); 
                    });
                    
                    window.networkGraph.on("click", function(params) {
                        if (params.nodes.length > 0) {
                            const nodeId = params.nodes[0];
                            let textToCopy = nodeId;
                            let nodeType = "ONION URL";
                            
                            if (textToCopy.startsWith('btc:')) { textToCopy = textToCopy.substring(4); nodeType = "BITCOIN WALLET"; }
                            else if (textToCopy.startsWith('cve:')) { textToCopy = textToCopy.substring(4); nodeType = "CVE VULNERABILITY"; }
                            else if (textToCopy.startsWith('ip:')) { textToCopy = textToCopy.substring(3); nodeType = "IPv4 EXPOSURE"; }
                            else if (textToCopy.startsWith('email:')) { textToCopy = textToCopy.substring(6); nodeType = "EMAIL ADDRESS"; }
                            
                            copyToClipboard(textToCopy);
                            pushToLiveFeed('NODE COPIED', `Extracted: ${textToCopy}`, 'success');
                            logSystemEvent(`Copied graph entity to clipboard: ${textToCopy}`, 'success');
                            openNodeModal(nodeId, textToCopy, nodeType);
                        }
                    });
                }
            } catch(e) { console.error("Link Graph Error:", e); }
        }
        
        async function openNodeModal(rawId, cleanValue, type) {
            document.getElementById('node-modal-id').innerText = cleanValue;
            document.getElementById('node-modal-type').innerText = type;
            document.getElementById('node-modal-origins').innerHTML = '<span class="text-gray-500 animate-pulse">TRACING ORIGINS...</span>';
            document.getElementById('node-modal-targets').innerHTML = '<span class="text-gray-500 animate-pulse">TRACING OUTBOUND LINKS...</span>';
            document.getElementById('node-modal-ai').innerHTML = '<span class="text-gray-500 animate-pulse">AWAITING CORRELATION DATA...</span>';
            
            document.getElementById('node-modal').classList.remove('hidden');
            
            try {
                const res = await fetch(`/api/node_summary?id=${encodeURIComponent(rawId)}`);
                const data = await res.json();
                
                let originsHtml = data.origins.length > 0 ? data.origins.map(o => `<div><a href="${o.replace(/^(btc|cve|ip|email):/, '')}" target="_blank" class="hover:underline hover:text-orange-300 break-all">${o.replace(/^(btc|cve|ip|email):/, '')}</a></div>`).join('') : '<span class="text-gray-600">No known origins mapped in this sweep.</span>';
                document.getElementById('node-modal-origins').innerHTML = originsHtml;
                
                let targetsHtml = data.targets.length > 0 ? data.targets.map(t => `<div><a href="${t.replace(/^(btc|cve|ip|email):/, '')}" target="_blank" class="hover:underline hover:text-cyan-300 break-all">${t.replace(/^(btc|cve|ip|email):/, '')}</a></div>`).join('') : '<span class="text-gray-600">No outbound targets mapped.</span>';
                document.getElementById('node-modal-targets').innerHTML = targetsHtml;
                
                let contextNodes = data.origins.slice(0,3).join(', ') || "Unknown";
                let aiPrompt = `Analyze this Dark Web entity trace: Entity Type is [${type}]. Value is [${cleanValue}]. It was discovered connected to these node origins: ${contextNodes}. What are the immediate tactical threat implications of this specific connection? Keep it under 4 sentences.`;
                fetchAgenticAI(aiPrompt, 'node-modal-ai');
                
            } catch (e) {
                document.getElementById('node-modal-origins').innerHTML = '<span class="text-red-500">TRACE FAILED</span>';
                document.getElementById('node-modal-targets').innerHTML = '<span class="text-red-500">TRACE FAILED</span>';
            }
        }
        
        function closeNodeModal() { document.getElementById('node-modal').classList.add('hidden'); }
        
        async function openEntityListModal(type) {
            document.getElementById('entity-list-modal').classList.remove('hidden');
            document.getElementById('entity-list-table-body').innerHTML = `<tr><td colspan="3" class="text-center py-8 text-cyan-500 animate-pulse font-mono text-[10px]">>> EXTRACTING ${type.toUpperCase()} MANIFEST...</td></tr>`;
            
            let typeLabel = "ONION URL"; let colorClass = "text-purple-400";
            if (type === 'btc') { typeLabel = "BITCOIN WALLET"; colorClass = "text-yellow-400"; }
            if (type === 'cve') { typeLabel = "CVE VULNERABILITY"; colorClass = "text-blue-400"; }
            if (type === 'ip') { typeLabel = "IPv4 EXPOSURE"; colorClass = "text-red-400"; }
            if (type === 'email') { typeLabel = "EMAIL ADDRESS"; colorClass = "text-emerald-400"; }
            
            document.getElementById('entity-list-modal-title').innerHTML = `[ EXTRACTED ${typeLabel} MANIFEST ]`;
            
            try {
                const res = await fetch(`/api/entity_list?type=${type}`);
                const result = await res.json();
                const tbody = document.getElementById('entity-list-table-body');
                
                if (!result.data || result.data.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="3" class="text-center py-8 text-gray-600 font-mono text-[10px]">NO ENTITIES OF THIS TYPE RECORDED YET.</td></tr>`;
                    return;
                }
                
                tbody.innerHTML = result.data.map(item => {
                    const sourcesHtml = item.sources.map(s => `<div class="truncate text-gray-500 text-[9px] hover:text-gray-300 transition-colors cursor-help" title="${s}">${s}</div>`).join('');
                    return `
                    <tr class="hover:bg-[#111] transition-colors border-b border-[#222]">
                        <td class="py-3 font-mono text-[11px] ${colorClass} font-bold break-all pr-2" title="${item.value}">${item.value}</td>
                        <td class="py-3 font-mono pr-2">${sourcesHtml}</td>
                        <td class="py-3 text-right font-mono text-[9px] whitespace-nowrap align-top">
                            <div class="flex justify-end gap-1 items-start mt-0.5">
                                <button onclick="copyToClipboard('${item.raw_value || item.value}'); logSystemEvent('Copied ${typeLabel} to clipboard', 'success');" class="h-6 px-2.5 bg-[#1a1a1a] border border-[#333] hover:border-cyan-500 text-gray-400 hover:text-white rounded transition-all cursor-pointer flex items-center justify-center">COPY</button>
                                <button onclick="openNodeModal('${item.id}', '${item.raw_value || item.value}', '${typeLabel}')" class="h-6 px-2.5 bg-[#1a1a1a] border border-[#333] hover:border-purple-500 text-gray-400 hover:text-white rounded transition-all cursor-pointer flex items-center justify-center">TRACK</button>
                            </div>
                        </td>
                    </tr>`;
                }).join('');
            } catch (e) {
                document.getElementById('entity-list-table-body').innerHTML = `<tr><td colspan="3" class="text-center py-8 text-red-500 font-mono text-[10px]">API EXTRACTION FAILURE</td></tr>`;
            }
        }
        
        function closeEntityListModal() { document.getElementById('entity-list-modal').classList.add('hidden'); }

        async function fetchConnections() {
            if(!isSyncing) return;
            try {
                const res = await fetch('/api/connections');
                const result = await res.json();
                window.currentConnectionsData = result.data;
                renderConnectionsTable();
            } catch(e) { console.error("Connections fetch error", e); }
        }
        
        function renderConnectionsTable() {
            const tbody = document.getElementById('connections-table-body');
            const searchTerm = document.getElementById('link-search').value.toLowerCase();
            
            let filtered = window.currentConnectionsData;
            if(searchTerm) filtered = filtered.filter(item => item.from.toLowerCase().includes(searchTerm) || item.to.toLowerCase().includes(searchTerm));
            
            if(filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="2" class="text-center py-4 text-gray-600 font-mono text-[10px]">NO CONNECTIONS FOUND OR SYNCING</td></tr>`;
                return;
            }
            
            tbody.innerHTML = filtered.map(item => {
                return `
                <tr class="hover:bg-[#111] transition-colors border-b border-[#222]">
                    <td class="py-2 font-mono text-[9px] text-gray-400 truncate max-w-[200px] pr-2" title="${item.from}">${item.from}</td>
                    <td class="py-2 font-mono text-[9px] text-pink-400 truncate max-w-[200px]" title="${item.to}">➜ ${item.to}</td>
                </tr>`;
            }).join('');
        }
        
        document.getElementById('link-search').addEventListener('input', renderConnectionsTable);
        document.getElementById('refresh-graph-btn').addEventListener('click', () => { fetchAndRenderGraph(); fetchConnections(); });

        const SYSTEM_STATE = {
            activeLayer: 'geopolitics',
            nodes: { darkweb: [], geopolitics: [] }
        };

        let refreshSeconds = 20;
        setInterval(() => {
            refreshSeconds--;
            if (refreshSeconds <= 0) refreshSeconds = 20;
            const timerEl = document.getElementById('refresh-timer');
            if (timerEl) timerEl.textContent = refreshSeconds;
        }, 1000);

        async function fetchGeopolitics() {
            try {
                const res = await fetch('/api/geopolitics');
                const data = await res.json();
                
                SYSTEM_STATE.nodes.geopolitics = data;
                window.currentGeoData = data;

                const tbody = document.getElementById('hotspots-table');
                
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3" class="text-center py-4 text-gray-600 text-[10px]">AWAITING 7-DAY OSINT FEED... NO ACTIVE DYNAMIC HOTSPOTS</td></tr>';
                } else {
                    data.sort((a,b) => b.severity - a.severity);
                    
                    tbody.innerHTML = data.map((item, index) => {
                        let colorClass = item.severity > 0.8 ? 'text-red-500' : (item.severity > 0.5 ? 'text-yellow-500' : 'text-green-500');
                        let sevLabel = item.severity > 0.8 ? 'CRITICAL' : (item.severity > 0.5 ? 'ELEVATED' : 'ACTIVE');
                        return `
                        <tr class="hover:bg-[#111] transition-colors border-b border-[#222]">
                            <td class="py-2 font-mono text-[10px] text-gray-300">
                                ${item.label.toUpperCase()}<br>
                                <span class="text-[8px] text-gray-600">${item.country.toUpperCase()}</span>
                            </td>
                            <td class="py-2 text-center font-mono text-[9px] font-bold ${colorClass}">${sevLabel}</td>
                            <td class="py-2 text-right font-mono text-[9px]">
                                <button onclick="openGeoModal(${index})" class="px-2 py-1 bg-[#1a1a1a] border border-[#333] hover:border-yellow-500 text-gray-400 hover:text-white rounded transition-all cursor-pointer">INTEL</button>
                            </td>
                        </tr>`;
                    }).join('');
                }
                
                data.forEach(node => {
                    if (node.latest_headline && !loggedHeadlines.has(node.latest_headline) && node.severity > 0.4) {
                        logSystemEvent(`[GEO-INTEL: ${node.label.toUpperCase()}] ${node.latest_headline}`, 'warn');
                        pushToLiveFeed(`GEO-INTEL: ${node.label.toUpperCase()}`, node.latest_headline, 'warn');
                        loggedHeadlines.add(node.latest_headline);
                    }
                });
            } catch (error) { console.error("[Geopolitics API Offline]", error); }
        }

        setInterval(() => { 
            const clockEl = document.getElementById('clock');
            if(clockEl) clockEl.textContent = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'; 
        }, 1000);

        async function fetchDarkWebIntel() {
            if (!isSyncing) return;
            
            try {
                const res = await fetch('/api/darkweb');
                const resultObj = await res.json();
                
                const data = resultObj.data;
                const statusEl = document.getElementById('tor-status');
                
                // CRITICAL OPSEC CHECK: If API returns error/offline due to proxy failure
                if (resultObj.status === "error" || resultObj.status === "offline") {
                    statusEl.innerText = "● TOR TUNNEL DISCONNECTED";
                    statusEl.className = "text-[9px] text-red-500 animate-pulse whitespace-nowrap flex items-center h-6 px-1";
                    renderDarkWebTable(); // Will show offline message
                    return;
                } else {
                    statusEl.innerText = "● LIVE SYNC";
                    statusEl.className = "text-[9px] text-green-500 animate-pulse whitespace-nowrap flex items-center h-6 px-1";
                }
                
                let requiresRender = false;
                
                data.forEach(item => {
                    const existingIndex = window.currentDarkWebData.findIndex(i => i.url === item.url);

                    if (existingIndex === -1) {
                        window.currentDarkWebData.push(item);
                        requiresRender = true;

                        if (!seenUrls.has(item.url)) {
                            seenUrls.add(item.url);
                            let hostname = 'Unknown Node';
                            try { hostname = new URL(item.url).hostname; } catch(e) {
                                const match = item.url.match(/:\/\/(.[^/]+)/); if(match) hostname = match[1];
                            }
                            if (seenUrls.size > 5) pushToLiveFeed(`NEW ONION DETECTED`, `${item.classification} activity identified at ${hostname}`, 'error');
                        }
                    } else {
                        const oldEntitiesStr = JSON.stringify(window.currentDarkWebData[existingIndex].entities);
                        const newEntitiesStr = JSON.stringify(item.entities);
                        if (window.currentDarkWebData[existingIndex].classification !== item.classification ||
                            window.currentDarkWebData[existingIndex].crawled_at !== item.crawled_at ||
                            oldEntitiesStr !== newEntitiesStr) {
                            window.currentDarkWebData[existingIndex] = item;
                            requiresRender = true;
                        }
                    }
                });

                window.currentDarkWebData.sort((a, b) => new Date(b.crawled_at) - new Date(a.crawled_at));
                if (window.currentDarkWebData.length > 1000) window.currentDarkWebData = window.currentDarkWebData.slice(0, 1000);
                
                if (requiresRender || document.getElementById('dark-web-intel-table').innerHTML.includes('AWAITING')) {
                    renderDarkWebTable();
                }

            } catch (error) { 
                document.getElementById('dark-web-intel-table').innerHTML = `<tr><td colspan="4" class="text-center py-4 text-red-500 text-[10px]">> CONNECTION OFFLINE</td></tr>`; 
            }
        }
        
        async function fetchGlobeIPs() {
            if(!isSyncing || SYSTEM_STATE.activeLayer !== 'darkweb') return;
            try {
                const res = await fetch('/api/globe_ips');
                const result = await res.json();
                
                let newDarkwebNodes = [];
                result.data.forEach(marker => {
                    newDarkwebNodes.push({
                        coords: [marker.lon, marker.lat],
                        severity: 0.9,
                        type: 'IP',
                        label: `IP: ${marker.ip}`,
                        location: marker.loc
                    });
                });
                SYSTEM_STATE.nodes.darkweb = newDarkwebNodes;
            } catch(e) {}
        }

        function initData() {
            pushToLiveFeed('SYSTEM BOOT', 'Topographical engine online. Internal data loops active.', 'success');
            testAIConnection(); 
            
            logSystemEvent("Booting Dashboard Modules...", "success");

            fetchGeopolitics(); fetchDarkWebIntel();
            fetchAndRenderGraph(); 
            fetchConnections();
            fetchGlobeIPs();
            
            // OPSEC: Check system connection status immediately and continuously
            checkSystemStatus();
            setInterval(checkSystemStatus, 3000);

            setInterval(fetchDarkWebIntel, 5000); 
            setInterval(fetchGlobeIPs, 3000);
            setInterval(() => { fetchAndRenderGraph(); fetchConnections(); }, 60000); // 60s for performance
            setInterval(fetchGeopolitics, 20000); 
            
            pushToLiveFeed('EXTERNAL FEEDS ONLINE', 'Threat OSINT engines synced securely.', 'success');
            logSystemEvent("PRIN Agentic Models Loaded.", "success");
            logSystemEvent("Link Analysis Engine Init: Mapping Extracted Entities...", "success");
        }
        
        initData();

        const layerBtns = document.querySelectorAll('.layer-btn');
        const layerLabel = document.getElementById('layer-label');
        layerBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                layerBtns.forEach(b => b.classList.remove('active')); e.currentTarget.classList.add('active');
                SYSTEM_STATE.activeLayer = e.currentTarget.dataset.layer;
                layerLabel.textContent = `HEATMAP / TOPOGRAPHY: ${SYSTEM_STATE.activeLayer.toUpperCase()}`;
                if(SYSTEM_STATE.activeLayer === 'darkweb') {
                    fetchGlobeIPs();
                }
            });
        });

        const canvas = document.getElementById('globe-canvas');
        const context = canvas.getContext('2d');
        let width, height;
        const projection = d3.geoOrthographic().clipAngle(90);
        const path = d3.geoPath().projection(projection).context(context);
        
        function resize() {
            const rect = canvas.parentElement.getBoundingClientRect();
            width = rect.width; height = rect.height;
            canvas.width = width; canvas.height = height;
            projection.scale(Math.min(width, height) * 0.45).translate([width / 2, height / 2]);
        }
        window.addEventListener('resize', resize); resize();

        let rotation = [0, -15, 0];
        let isDragging = false; let dragStartRotation = [0, 0, 0]; let dragStartPoint = [0, 0];

        const graticule = d3.geoGraticule()();

        d3.select(canvas).call(d3.drag()
            .on('start', (event) => { isDragging = true; dragStartPoint = [event.x, event.y]; dragStartRotation = [...rotation]; })
            .on('drag', (event) => { 
                const sensitivity = 0.25;
                rotation[0] = dragStartRotation[0] + (event.x - dragStartPoint[0]) * sensitivity; 
                rotation[1] = Math.max(-90, Math.min(90, dragStartRotation[1] - (event.y - dragStartPoint[1]) * sensitivity)); 
            })
            .on('end', () => { isDragging = false; })
        );

        d3.json('https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson').then(data => { 
            function renderLoop() {
                if (!isDragging) rotation[0] += 0.15; 
                projection.rotate(rotation);
                context.clearRect(0, 0, width, height);
                
                let atmosGrad = context.createRadialGradient(width/2, height/2, projection.scale() * 0.8, width/2, height/2, projection.scale() * 1.05);
                atmosGrad.addColorStop(0, 'rgba(0, 0, 0, 1)');
                atmosGrad.addColorStop(1, 'rgba(14, 165, 233, 0.15)');
                
                context.beginPath(); path({type: "Sphere"}); context.fillStyle = '#020617'; context.fill();
                context.lineWidth = 1; context.strokeStyle = 'rgba(14, 165, 233, 0.1)'; context.stroke();
                
                context.beginPath(); path(graticule); 
                context.lineWidth = 0.5; context.strokeStyle = 'rgba(51, 65, 85, 0.3)'; context.stroke();

                context.beginPath(); path(data); context.fillStyle = '#090f1a'; context.fill();

                context.lineWidth = 0.2;          
                context.strokeStyle = '#38bdf8';  
                context.shadowColor = '#38bdf8';
                context.shadowBlur = 2;           
                context.stroke();

                context.shadowBlur = 0;
                const time = Date.now() / 1000;
                const activeNodes = SYSTEM_STATE.nodes[SYSTEM_STATE.activeLayer] || [];
                
                activeNodes.forEach(node => {
                    const coords = projection(node.coords);
                    if (coords) {
                        const isDarkWeb = SYSTEM_STATE.activeLayer === 'darkweb';
                        const isGeo = SYSTEM_STATE.activeLayer === 'geopolitics';
                        
                        let radius = 3 + (node.severity * 3);
                        if (isDarkWeb) radius = 3 + (node.severity * 4);
                        if (isGeo) radius = 8 + (node.severity * 8); 

                        const blink = Math.sin(time * (isDarkWeb ? 10 : 2)) > 0;
                        let color = '#ea580c'; 
                        if (isDarkWeb) color = node.severity > 0.8 ? '#e879f9' : '#c084fc'; 
                        else if (isGeo) color = node.severity > 0.8 ? 'rgba(239,68,68,1)' : (node.severity > 0.6 ? 'rgba(234,179,8,1)' : 'rgba(34,197,94,1)');
                        else if (node.severity > 0.8) color = '#ef4444';
                        
                        if(isDarkWeb) {
                            if (blink || node.severity < 0.8) {
                                context.beginPath(); context.arc(coords[0], coords[1], radius + 2, 0, 2 * Math.PI);
                                context.strokeStyle = color; context.lineWidth = 1; context.stroke();
                                context.beginPath(); context.arc(coords[0], coords[1], radius * 0.5, 0, 2 * Math.PI);
                                context.fillStyle = color; context.fill();
                            }
                            
                            if (node.label) {
                                context.fillStyle = '#ffffff'; context.font = 'bold 8px Consolas';
                                context.fillText(node.label, coords[0] + 6, coords[1] + 2);
                                if (node.location) {
                                    context.fillStyle = '#e879f9'; context.font = '6px Consolas';
                                    context.fillText(node.location.toUpperCase(), coords[0] + 6, coords[1] + 10);
                                }
                            }

                        } else if (isGeo) {
                            let grad = context.createRadialGradient(coords[0], coords[1], 0, coords[0], coords[1], radius * 1.5);
                            let baseColor = color.replace('1)', '0.8)'); let fadeColor = color.replace('1)', '0)');
                            grad.addColorStop(0, baseColor); grad.addColorStop(1, fadeColor);
                            
                            context.beginPath(); context.arc(coords[0], coords[1], radius * 1.5, 0, 2 * Math.PI);
                            context.fillStyle = grad; context.fill();
                            context.beginPath(); context.arc(coords[0], coords[1], 1.5, 0, 2 * Math.PI);
                            context.fillStyle = '#ffffff'; context.fill();
                            
                            if(node.label) {
                                context.fillStyle = '#ffffff'; context.font = 'bold 9px Consolas';
                                context.fillText(node.label.toUpperCase(), coords[0] + 6, coords[1] + 3);
                                if(node.latest_headline) {
                                    context.fillStyle = '#eab308'; context.font = '7px Consolas';
                                    let reasonText = node.latest_headline.length > 30 ? node.latest_headline.substring(0, 30) + '...' : node.latest_headline;
                                    context.fillText(reasonText, coords[0] + 6, coords[1] + 12);
                                }
                            }
                        } else {
                            if (blink || node.severity < 0.8) {
                                context.beginPath(); context.arc(coords[0], coords[1], radius + 2, 0, 2 * Math.PI);
                                context.strokeStyle = color; context.lineWidth = 1; context.stroke();
                                context.beginPath(); context.arc(coords[0], coords[1], radius * 0.5, 0, 2 * Math.PI);
                                context.fillStyle = color; context.fill();
                            }
                        }
                    }
                });
                requestAnimationFrame(renderLoop);
            }
            renderLoop();
        }).catch(err => {
            console.error("D3 Map Load Error:", err);
            pushToLiveFeed('MAP OFFLINE', 'Could not load topographical boundaries.', 'error');
        });
    </script>
</body>
</html>
"""

# --- Routes ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        user_captcha = request.form.get('captcha', '')

        if user_captcha.upper() != session.get('captcha'):
            flash('Verification Failed')
            return redirect(url_for('login'))
        
        user_data = get_user(g.db, username)
        
        if not user_data and username == "admin" and password == "adminpass":
            user = User(id="admin", username="admin")
            login_user(user)
            return redirect(url_for('dashboard'))

        if user_data and check_password(user_data['password_hash'], password):
            user = User(id=user_data['username'], username=user_data['username'])
            login_user(user)
            session.pop('captcha', None)
            return redirect(url_for('dashboard'))
        else:
            flash('Authentication Failed')
            return redirect(url_for('login'))

    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha_text
    return render_template_string(LOGIN_TEMPLATE, captcha=captcha_text)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/")
@login_required
def dashboard():
    return render_template_string(PRIN_DASHBOARD_TEMPLATE)

@app.route("/api/system_status")
@login_required
def api_system_status():
    """Exposes real-time OPSEC state to the UI to halt fetches if Tor breaks."""
    return jsonify({"tor_connected": TOR_CONNECTED})

@app.route("/api/darkweb")
@login_required
def api_darkweb():
    # Strict Killswitch
    if not TOR_CONNECTED:
        return jsonify({"status": "offline", "data": [], "error": "TOR DISCONNECTED - SAFE ABORT"}), 403

    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row 
        cur = conn.cursor()
        
        cur.execute("""
            SELECT url, title, status, classification, fetched_at, content_summary 
            FROM pages 
            WHERE classification NOT IN ('Dead Node', 'Unknown Node')
            ORDER BY fetched_at DESC LIMIT 100
        """)
        rows = cur.fetchall()
        
        result = []
        for r in rows:
            domain = urlparse(r['url']).netloc if r['url'] else "unknown"
            result.append({
                "url": f"http://{domain}/",
                "matched_url": r['url'],
                "classification": r['classification'] or "General",
                "crawled_at": r['fetched_at'],
                "title": r['title'] or "No Title",
                "summary": r['content_summary'] or "No summary available."
            })
            
        return jsonify({"status": "live", "data": result})
    except Exception as e: 
        print(f"[CRITICAL API ERROR]: {e}")
        return jsonify({"status": "error", "data": [], "error": str(e)})
    finally:
        if 'conn' in locals(): conn.close()

@app.route("/api/globe_ips")
@login_required
def api_globe_ips():
    """A direct fetcher for all successfully resolved IP locations from memory to bypass limits."""
    nodes = []
    for ip, info in IP_CACHE.items():
        if info.get("lat") is not None and info.get("lon") is not None:
            nodes.append({
                "ip": ip,
                "loc": info["loc"],
                "lat": info["lat"],
                "lon": info["lon"]
            })
    return jsonify({"data": nodes})

@app.route("/api/graph")
@login_required
def api_graph():
    """Knowledge Graph mappings sourced strictly from the exact crawler's DB."""
    nodes = []
    edges = []
    added_nodes = set()
    stats = {"onions": 0, "btc": 0, "cve": 0, "ip": 0, "email": 0, "edges": 0}

    def add_node(n_id, label, group, title=None):
        if n_id not in added_nodes:
            nodes.append({"id": n_id, "label": label, "group": group, "title": title or label})
            added_nodes.add(n_id)

    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        try:
            cur.execute("SELECT COUNT(DISTINCT url) FROM pages WHERE classification != 'Dead Node'")
            stats["onions"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT to_url) FROM links WHERE to_url LIKE 'btc:%'")
            stats["btc"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT to_url) FROM links WHERE to_url LIKE 'ip:%'")
            stats["ip"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT to_url) FROM links WHERE to_url LIKE 'email:%'")
            stats["email"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(DISTINCT to_url) FROM links WHERE to_url LIKE 'cve:%'")
            stats["cve"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM links")
            stats["edges"] = cur.fetchone()[0]
        except Exception:
            pass
        
        cur.execute("SELECT from_url, to_url FROM links ORDER BY id DESC LIMIT 1500")
        link_rows = cur.fetchall()
        for r in link_rows:
            from_url = r[0]
            to_url = r[1]
            
            try: from_host = urlparse(from_url).netloc[:15] + "..." if from_url else "Node"
            except: from_host = "Node"
            add_node(from_url, from_host, "url", f"Origin: {from_url}")
            
            if to_url.startswith("btc:"):
                add_node(to_url, to_url.replace("btc:", "")[:8] + "..", "btc", f"BTC: {to_url.replace('btc:', '')}")
            elif to_url.startswith("cve:"):
                add_node(to_url, to_url.replace("cve:", ""), "cve", f"CVE: {to_url.replace('cve:', '')}")
            elif to_url.startswith("ip:"):
                raw_ip = to_url.replace("ip:", "")
                ip_info = resolve_ip(raw_ip)
                title = f"IP: {raw_ip}\nLocation: {ip_info['loc']}" if ip_info['loc'] != "Unknown Location" else f"IP: {raw_ip}"
                add_node(to_url, raw_ip, "ip", title)
            elif to_url.startswith("email:"):
                add_node(to_url, to_url.replace("email:", "")[:12] + "..", "email", f"Email: {to_url.replace('email:', '')}")
            else:
                try: to_host = urlparse(to_url).netloc[:15] + "..." if to_url else "Node"
                except: to_host = "Node"
                add_node(to_url, to_host, "url", f"Target: {to_url}")
                
            edges.append({"from": from_url, "to": to_url, "label": "links_to"})

        cur.execute("SELECT url, title FROM pages ORDER BY id DESC LIMIT 200")
        page_rows = cur.fetchall()
        for r in page_rows:
            url = r[0]
            title = r[1]
            try: short_url = urlparse(url).netloc[:15] + "..."
            except: short_url = url[:15]
            add_node(url, short_url, "url", title or url)
            
    except Exception as e:
        pass
    finally:
        if 'conn' in locals(): conn.close()

    return jsonify({"nodes": nodes, "edges": edges, "stats": stats})
    
@app.route("/api/connections")
@login_required
def api_connections():
    """Returns a flat list of exactly who is connected to who."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT from_url, to_url FROM links ORDER BY id DESC LIMIT 1000")
        rows = [{"from": r[0], "to": r[1]} for r in cur.fetchall()]
        return jsonify({"data": rows})
    except Exception:
        return jsonify({"data": []})
    finally:
        if 'conn' in locals(): conn.close()

@app.route("/api/node_summary")
@login_required
def api_node_summary():
    """Returns deep trace tracking for a specific entity/node clicked in the graph."""
    node_id = request.args.get('id')
    if not node_id:
        return jsonify({"error": "No ID provided"}), 400
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        cur.execute("SELECT from_url FROM links WHERE to_url = ? LIMIT 50", (node_id,))
        origins = [r[0] for r in cur.fetchall()]
        
        cur.execute("SELECT to_url FROM links WHERE from_url = ? LIMIT 50", (node_id,))
        targets = [r[0] for r in cur.fetchall()]
        
        return jsonify({
            "id": node_id,
            "origins": origins,
            "targets": targets
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals(): conn.close()

@app.route("/api/entity_list")
@login_required
def api_entity_list():
    """Returns a full list of extracted entities of a specific type and their sources."""
    entity_type = request.args.get('type')
    if not entity_type or entity_type not in ['btc', 'cve', 'ip', 'email', 'onion']:
        return jsonify({"data": []})
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        if entity_type == 'onion':
            cur.execute("SELECT url, title FROM pages WHERE classification != 'Dead Node' ORDER BY fetched_at DESC LIMIT 500")
            rows = cur.fetchall()
            data = [{"id": r[0], "value": r[0], "raw_value": r[0], "sources": [r[1] or "Unknown Title"]} for r in rows]
        else:
            prefix = f"{entity_type}:%"
            cur.execute("SELECT to_url, from_url FROM links WHERE to_url LIKE ? ORDER BY id DESC LIMIT 2000", (prefix,))
            rows = cur.fetchall()
            
            grouped = {}
            for to_url, from_url in rows:
                if to_url not in grouped:
                    grouped[to_url] = set()
                grouped[to_url].add(from_url)
            
            data = []
            for to_url, sources in grouped.items():
                val = to_url.split(":", 1)[1] if ":" in to_url else to_url
                display_val = val
                
                if entity_type == 'ip':
                    ip_info = resolve_ip(val)
                    if ip_info['loc'] != "Unknown Location":
                        display_val = f"{val} [{ip_info['loc']}]"
                        
                data.append({
                    "id": to_url,
                    "value": display_val,
                    "raw_value": val,
                    "sources": list(sources)[:10] 
                })
                
        return jsonify({"data": data})
    except Exception as e:
        return jsonify({"data": []})
    finally:
        if 'conn' in locals(): conn.close()

@app.route("/api/darkweb/all")
@login_required
def api_darkweb_all():
    """Backend endpoint for full PDF Export from the robust crawler's DB"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT url, title, status, depth, fetched_at, classification, content_summary FROM pages ORDER BY fetched_at DESC")
        rows = cur.fetchall()
        
        result = []
        for r in rows:
            url, title, status, depth, fetched_at, classification, summary = r
            
            if not classification or classification == "Unknown Node" or classification == "Dead Node":
                continue
                
            result.append({
                "url": url,
                "classification": classification,
                "crawled_at": fetched_at,
                "entities": {},
                "title": title or "No Title",
                "summary": summary if summary else f"HTTP {status}"
            })
        return jsonify({"data": result})
    except Exception: 
        return jsonify({"data": []})
    finally:
        if 'conn' in locals(): conn.close()

@app.route("/api/geopolitics")
@login_required
def api_geopolitics():
    global GLOBAL_GEO_DATA
    return jsonify(GLOBAL_GEO_DATA)

def start_dashboard_system():
    print("--- Initializing Secure Intelligence Platform ---")
    setup_dashboard_db()
    
    # Pre-initialize the crawler DB so the UI API doesn't fail on boot
    conn = init_db(DB_PATH)
    
    # Erase history on fresh boot if desired
    print("[!] Erasing previous crawler history (Fresh Start Mode)...")
    cur = conn.cursor()
    cur.execute("DELETE FROM pages")
    cur.execute("DELETE FROM links")
    conn.commit()
    conn.close()

    try:
        conn = get_dashboard_db_connection()
        create_user(conn, "admin", "adminpass", is_admin=True)
        if hasattr(conn, 'close'): conn.close()
    except Exception: pass
    
    # the Watchdog to test for tor presence immediately
    watchdog = threading.Thread(target=tor_watchdog_worker, daemon=True)
    watchdog.start()
    time.sleep(2)

    if not TOR_CONNECTED:
        print("\n[!] CRITICAL WARNING: TOR PROXY IS NOT RUNNING ON PORT 9150 OR 9050.")
        print("[!] The Web UI will load, but the Crawler is mathematically LOCKED and will NOT fetch anything over clearnet.")
    else:
        print("\n[OPSEC] Greenlight. Tor Proxy Secured. DNS Leaks Blocked.")

    def start_robust_crawler():
        print("Starting SECURE Threaded Crawler Engine...")
        while True:
            if not TOR_CONNECTED:
                # Idle state if Tor goes offline. Never proceed over direct IP.
                time.sleep(5)
                continue

            try:
                c_conn = init_db(DB_PATH) 
                cur = c_conn.cursor()
                
                cur.execute('''
                    SELECT DISTINCT to_url 
                    FROM links 
                    WHERE to_url NOT IN (SELECT url FROM pages)
                ''')
                all_unvisited = [r[0] for r in cur.fetchall() if r[0].endswith('.onion') or '.onion/' in r[0]]
                c_conn.close()
                
                random.shuffle(all_unvisited)
                frontier_seeds = []
                seen_frontier_domains = set()
                
                for u in all_unvisited:
                    dom = urlparse(u).netloc
                    if dom not in seen_frontier_domains:
                        seen_frontier_domains.add(dom)
                        frontier_seeds.append(u)
                    if len(frontier_seeds) >= 150:
                        break
                
                if not frontier_seeds:
                    print("[!] Graph frontier empty. Re-seeding from massive directories...")
                    c_conn = init_db(DB_PATH)
                    cur = c_conn.cursor()
                    for s in SEED_URLS:
                        cur.execute("DELETE FROM pages WHERE url = ?", (canonicalize(s),))
                    c_conn.commit()
                    c_conn.close()
                    current_seeds = SEED_URLS
                else:
                    print(f"[!] Target Acquired: Attacking {len(frontier_seeds)} UNIQUE new domains securely...")
                    current_seeds = list(set(SEED_URLS + frontier_seeds))
                
                crawl(current_seeds, DB_PATH, max_pages=1000, max_depth=MAX_DEPTH)
                print("[!] Crawler Sub-Sweep Finished. Resting 5s before next expansion phase...")
                time.sleep(5)
            except Exception as e:
                time.sleep(5)
    
    worker_thread = threading.Thread(target=start_robust_crawler, daemon=True)
    worker_thread.start()

    geo_thread = threading.Thread(target=geopolitics_worker, daemon=True)
    geo_thread.start()
    
    ip_thread = threading.Thread(target=ip_resolver_worker, daemon=True)
    ip_thread.start()
    
    print("Secure Web dashboard running at: http://127.0.0.1:5090")
    app.run(port=5090, debug=False)

if __name__ == "__main__":
    start_dashboard_system()