import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from app.utils.db_handler import DatabaseManager


st.set_page_config(
    page_title="AI-Driven TLS Fingerprinting Dashboard",
    page_icon="🔐",
    layout="wide"
)


# ---------------------------------
# RESOURCE / STYLE
# ---------------------------------

@st.cache_resource
def get_db() -> DatabaseManager:
    return DatabaseManager()


def load_css() -> None:
    # Inject Remix Icons (cyberpunk-friendly icon set)
    st.markdown(
        '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/remixicon@4.3.0/fonts/remixicon.css">',
        unsafe_allow_html=True
    )
    css_path = Path("app/ui/style.css")
    if css_path.exists():
        css = css_path.read_text(encoding="utf-8")
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


# ---------------------------------
# TSHARK / SETTINGS HELPERS
# ---------------------------------

def resolve_tshark_path(db: DatabaseManager) -> str:
    return (
        db.get_config("tshark_path")
        or os.environ.get("TSHARK_PATH")
        or shutil.which("tshark")
        or r"C:\Program Files\Wireshark\tshark.exe"
    )


def get_detected_interfaces(db: DatabaseManager) -> List[dict]:
    """
    Öncelik:
    1. Host capture agent tarafından paylaşılan JSON dosyası
    2. Native / non-docker kullanımda local tshark -D fallback
    """
    runtime_file = Path("data/runtime/detected_interfaces.json")

    if runtime_file.exists():
        try:
            data = json.loads(runtime_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception:
            pass

    tshark_path = resolve_tshark_path(db)

    try:
        result = subprocess.run(
            [tshark_path, "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8"
        )
    except FileNotFoundError:
        return []
    except Exception:
        return []

    if result.returncode != 0:
        return []

    interfaces = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split(". ", 1)
        if len(parts) == 2 and parts[0].isdigit():
            interfaces.append({
                "index": parts[0],
                "label": parts[1],
                "display": line
            })
        else:
            interfaces.append({
                "index": "",
                "label": line,
                "display": line
            })

    return interfaces


def get_current_config(db: DatabaseManager) -> dict:
    return {
        "capture_interface": db.get_config("capture_interface", "") or "",
        "tshark_path": resolve_tshark_path(db),
        "capture_filter": db.get_config("capture_filter", "") or "",
        "ring_duration": int(db.get_config("ring_duration", "30") or 30),
        "ring_files": int(db.get_config("ring_files", "10") or 10),
        "poll_interval": int(db.get_config("poll_interval", "5") or 5),
        "stable_seconds": int(db.get_config("stable_seconds", "3") or 3),
        "dashboard_port": int(db.get_config("dashboard_port", "8501") or 8501),
    }


# ---------------------------------
# CYBERPUNK PLOTLY THEME
# ---------------------------------

CYBER_COLORS = ["#00ff41", "#00d4ff", "#ff00a0", "#ffe600", "#b400ff", "#ff6600"]


def cyber_layout(fig: go.Figure, **kwargs) -> go.Figure:
    """Apply cyberpunk dark theme to all Plotly figures."""
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(7,7,16,0.95)",
        font=dict(
            color="#3a7a4f",
            family="'Share Tech Mono', monospace",
            size=11,
        ),
        margin=dict(l=10, r=10, t=28, b=10),
        xaxis=dict(
            gridcolor="rgba(0,255,65,0.07)",
            zerolinecolor="rgba(0,255,65,0.15)",
            tickfont=dict(color="#2a5c4a", family="'Share Tech Mono', monospace"),
            linecolor="rgba(0,255,65,0.2)",
        ),
        yaxis=dict(
            gridcolor="rgba(0,255,65,0.07)",
            zerolinecolor="rgba(0,255,65,0.15)",
            tickfont=dict(color="#2a5c4a", family="'Share Tech Mono', monospace"),
            linecolor="rgba(0,255,65,0.2)",
        ),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#3a7a4f"),
        ),
        **kwargs,
    )
    return fig


# ---------------------------------
# SMALL UI HELPERS
# ---------------------------------

def render_hero() -> None:
    st.markdown(
        """
        <div class="app-hero">
            <div class="app-hero-eyebrow">
                <i class="ri-shield-keyhole-fill hero-icon-shield"></i>
                <span class="app-hero-tagline">AUTONOMOUS NETWORK INTELLIGENCE PLATFORM</span>
            </div>
            <div class="app-hero-title">
                <i class="ri-radar-line hero-icon-radar"></i>
                AI-Driven TLS Fingerprinting
            </div>
            <div class="app-hero-subtitle">
                Autonomous characterization and verification framework for privacy-preserving TLS/SSL application identification.
            </div>
            <div class="hero-chip-row">
                <span class="hero-chip"><i class="ri-code-s-slash-line"></i> ClientHello Metadata</span>
                <span class="hero-chip"><i class="ri-fingerprint-2-line"></i> JA3 Fingerprinting</span>
                <span class="hero-chip"><i class="ri-database-2-line"></i> SQLite Whitelist</span>
                <span class="hero-chip"><i class="ri-broadcast-line"></i> Live Capture Monitoring</span>
                <span class="hero-chip"><i class="ri-terminal-box-line"></i> Operational Console</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_metric_card(label: str, value: str, footnote: str = "") -> str:
    footnote_html = f'<div class="metric-footnote">{footnote}</div>' if footnote else ""
    return f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        {footnote_html}
    </div>
    """


def get_status_badge(text: str, kind: str = "neutral") -> str:
    kind_map = {
        "success": "badge-success",
        "warning": "badge-warning",
        "danger":  "badge-danger",
        "info":    "badge-info",
        "neutral": "badge-neutral",
    }
    css_class = kind_map.get(kind, "badge-neutral")
    return f'<span class="badge {css_class}">{text}</span>'


def empty_state(title: str, text: str) -> None:
    st.markdown(
        f"""
        <div class="empty-state">
            <div class="empty-state-title">[ {title} ]</div>
            <div class="empty-state-text">// {text}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def format_file_size(size: Optional[int]) -> str:
    if size is None:
        return "-"
    size = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def render_capture_config_warning(db: DatabaseManager) -> None:
    configured_interface = db.get_config("capture_interface", "") or ""
    if not configured_interface:
        st.warning(
            "⚠ Capture interface configured değil. Live capture başlatmak için "
            "Settings sayfasından bir interface seçip kaydet."
        )


# Maps page names to (remix-icon-class, colour-var)
_SECTION_ICONS: dict = {
    "Event Trend":                 ("ri-pulse-line",              "var(--neon-green)"),
    "Top Predictions":             ("ri-bar-chart-grouped-line",   "var(--neon-cyan)"),
    "Top Destination Ports":       ("ri-router-line",              "var(--neon-magenta)"),
    "Top JA3 Hashes":              ("ri-fingerprint-2-line",       "var(--neon-yellow)"),
    "Recent TLS Detections":       ("ri-shield-flash-line",        "var(--neon-green)"),
    "Recent Platform Activity":    ("ri-rss-line",                 "var(--neon-cyan)"),
    "Live Monitor":                ("ri-live-line",                "var(--neon-green)"),
    "Current Operational State":   ("ri-cpu-line",                 "var(--neon-cyan)"),
    "Recent Detections":           ("ri-shield-flash-line",        "var(--neon-magenta)"),
    "Backend Activity Feed":       ("ri-terminal-box-line",        "var(--neon-yellow)"),
    "PCAP Explorer":               ("ri-folder-shield-2-line",     "var(--neon-green)"),
    "File Detail View":            ("ri-file-search-line",         "var(--neon-cyan)"),
    "Fingerprint Intelligence":    ("ri-scan-2-line",              "var(--neon-magenta)"),
    "Top JA3 Fingerprints":        ("ri-fingerprint-line",         "var(--neon-green)"),
    "Prediction Distribution":     ("ri-bubble-chart-line",        "var(--neon-cyan)"),
    "Destination Port Distribution":("ri-router-line",             "var(--neon-yellow)"),
    "Recent Unique Fingerprints":  ("ri-eye-2-line",              "var(--neon-magenta)"),
    "Whitelist Management":        ("ri-shield-check-line",        "var(--neon-green)"),
    "Candidate Queue":             ("ri-crosshair-2-line",         "var(--neon-cyan)"),
    "System Console":              ("ri-terminal-box-fill",        "var(--neon-green)"),
    "Settings & Capture Configuration": ("ri-settings-4-line",    "var(--neon-cyan)"),
}


def section_header(title: str, note: str = "") -> None:
    icon_class, color = _SECTION_ICONS.get(title, ("ri-arrow-right-s-line", "var(--neon-green)"))
    note_html = f'<div class="table-note">{note}</div>' if note else ""
    st.markdown(
        f'<div class="section-title">'
        f'<i class="{icon_class}" style="color:{color};margin-right:0.45rem;font-size:1rem;vertical-align:-2px;"></i>'
        f'{title}</div>{note_html}',
        unsafe_allow_html=True
    )


# ---------------------------------
# SIDEBAR
# ---------------------------------

# Icon + label mapping for sidebar navigation radio
_NAV_ITEMS = [
    ("📊", "Overview"),
    ("📡", "Live Monitor"),
    ("🗂", "PCAP Explorer"),
    ("🔬", "Fingerprint Intelligence"),
    ("🛡", "Whitelist"),
    ("🎯", "Candidates"),
    ("💻", "System Console"),
    ("⚙", "Settings"),
]
_NAV_LABELS  = [f"{icon}  {label}" for icon, label in _NAV_ITEMS]
_LABEL_TO_PAGE = {f"{icon}  {label}": label for icon, label in _NAV_ITEMS}


def render_sidebar() -> dict:
    with st.sidebar:
        # ── Brand block ──────────────────────────────────────────
        st.markdown(
            """
            <div class="nav-brand">
                <div class="nav-brand-icon"><i class="ri-shield-keyhole-fill"></i></div>
                <div>
                    <div class="nav-brand-title">TLS_FINGERPRINT</div>
                    <div class="nav-brand-sub">AI INTELLIGENCE PLATFORM</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            """
            <div class="nav-helper">
                <div class="nav-helper-title"><i class="ri-compass-discover-line"></i>&nbsp; Navigation</div>
                <div class="nav-helper-text">
                    Switch between operational views, intelligence summaries,
                    PCAP tracking, whitelist management and system console logs.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        selected_label = st.radio(
            "Workspace",
            _NAV_LABELS,
            label_visibility="collapsed"
        )
        page = _LABEL_TO_PAGE.get(selected_label, "Overview")

        st.markdown(
            """
            <div class="nav-helper">
                <div class="nav-helper-title"><i class="ri-equalizer-2-line"></i>&nbsp; Display Controls</div>
                <div class="nav-helper-text">
                    These settings only affect what is shown on screen.
                    They do not modify capture or backend processing.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        table_limit = st.slider("Table row limit", 10, 300, 50, 10)

        if st.button("⟳  SYNC"):
            st.rerun()

        st.markdown(
            """
            <div class="nav-helper">
                <div class="nav-helper-title"><i class="ri-terminal-box-line"></i>&nbsp; Operator Tips</div>
                <div class="nav-helper-text">
                    <b style="color:var(--neon-green)">📊 Overview</b> → system health<br>
                    <b style="color:var(--neon-green)">📡 Live Monitor</b> → backend feed<br>
                    <b style="color:var(--neon-green)">🗂 PCAP Explorer</b> → file lifecycle<br>
                    <b style="color:var(--neon-green)">💻 System Console</b> → debug logs
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    return {
        "page": page,
        "table_limit": table_limit,
    }


# ---------------------------------
# PAGE: OVERVIEW
# ---------------------------------

def render_overview(db: DatabaseManager, table_limit: int) -> None:
    render_capture_config_warning(db)

    metrics         = db.get_summary_metrics()
    recent_events   = db.get_recent_events(limit=table_limit)
    event_trend     = db.get_event_trend(limit=24)
    top_predictions = db.get_top_predictions(limit=10)
    top_ports       = db.get_port_distribution(limit=10)
    top_ja3         = db.get_top_ja3_hashes(limit=10)
    recent_logs     = db.get_recent_logs(limit=8)

    last_pcap     = metrics.get("last_processed_pcap") or "No processed file yet"
    capture_state = "Active / Monitoring" if metrics.get("active_pcap_jobs", 0) > 0 else "Idle / Waiting"

    # ── Row 1 ──────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(render_metric_card("System Status", "Online", "Dashboard and database are reachable"), unsafe_allow_html=True)
    with col2:
        st.markdown(render_metric_card("Capture / Watcher", capture_state, f"Active jobs: {metrics.get('active_pcap_jobs', 0)}"), unsafe_allow_html=True)
    with col3:
        st.markdown(render_metric_card("Total Events", str(metrics.get("total_events", 0)), f"Processed PCAPs: {metrics.get('processed_pcap_count', 0)}"), unsafe_allow_html=True)
    with col4:
        st.markdown(render_metric_card("Last Processed PCAP", last_pcap, "Most recently completed file"), unsafe_allow_html=True)

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    # ── Row 2 ──────────────────────────────────────────────────
    col5, col6, col7, col8 = st.columns(4)
    with col5:
        st.markdown(render_metric_card("Known Events",      str(metrics.get("known_events", 0))),     unsafe_allow_html=True)
    with col6:
        st.markdown(render_metric_card("Unknown Events",    str(metrics.get("unknown_events", 0))),   unsafe_allow_html=True)
    with col7:
        st.markdown(render_metric_card("Candidates",        str(metrics.get("candidate_count", 0))),  unsafe_allow_html=True)
    with col8:
        st.markdown(render_metric_card("Whitelist Entries", str(metrics.get("whitelist_count", 0))),  unsafe_allow_html=True)

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

    # ── Charts row 1 ───────────────────────────────────────────
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        section_header("Event Trend", "Hourly event volume based on processed TLS events.")
        if event_trend:
            df  = pd.DataFrame(event_trend)
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df["hour_bucket"], y=df["event_count"],
                mode="lines+markers",
                line=dict(color="#00ff41", width=2),
                marker=dict(color="#00ff41", size=5,
                            line=dict(color="#00ff41", width=1)),
                fill="tozeroy",
                fillcolor="rgba(0,255,65,0.07)",
                name="Events",
            ))
            cyber_layout(fig, xaxis_title="", yaxis_title="Events")
            st.plotly_chart(fig, use_container_width=True)
        else:
            empty_state("No Event Trend Yet", "Once traffic is processed, hourly event volume will appear here.")

    with chart_col2:
        section_header("Top Predictions", "Most frequent application guesses or whitelist matches.")
        if top_predictions:
            df  = pd.DataFrame(top_predictions)
            fig = px.bar(df, x="prediction", y="hit_count",
                         color_discrete_sequence=["#00d4ff"])
            cyber_layout(fig, xaxis_title="", yaxis_title="Hits")
            st.plotly_chart(fig, use_container_width=True)
        else:
            empty_state("No Prediction Data", "Predictions will appear here after JA3 records are processed.")

    # ── Charts row 2 ───────────────────────────────────────────
    lower_col1, lower_col2 = st.columns(2)

    with lower_col1:
        section_header("Top Destination Ports", "Ports most frequently observed in TLS events.")
        if top_ports:
            df  = pd.DataFrame(top_ports)
            fig = px.pie(df, names="dst_port", values="hit_count",
                         color_discrete_sequence=CYBER_COLORS, hole=0.48)
            fig.update_traces(
                textfont_color="#c8ffd4",
                marker=dict(line=dict(color="#070710", width=2)),
            )
            cyber_layout(fig)
            st.plotly_chart(fig, use_container_width=True)
        else:
            empty_state("No Port Distribution Yet", "Port distribution becomes visible after live traffic or PCAP processing.")

    with lower_col2:
        section_header("Top JA3 Hashes", "Most frequently observed JA3 fingerprints.")
        if top_ja3:
            df = pd.DataFrame(top_ja3)[["ja3_hash", "hit_count", "latest_prediction", "last_seen"]]
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            empty_state("No JA3 Fingerprints Yet", "Detected JA3 fingerprints will be summarized here.")

    # ── Recent Detections ───────────────────────────────────────
    section_header("Recent TLS Detections", "Latest processed TLS events from the pipeline.")
    if recent_events:
        df   = pd.DataFrame(recent_events)
        cols = [c for c in ["timestamp", "src_ip", "dst_ip", "dst_port", "ja3_hash", "prediction", "confidence", "status"] if c in df.columns]
        st.dataframe(df[cols], use_container_width=True, hide_index=True)
    else:
        empty_state("No Recent Events", "The backend is ready. Once capture or PCAP processing begins, detections will show up here.")

    # ── Recent Platform Activity ────────────────────────────────
    section_header("Recent Platform Activity", "Latest backend logs from capture, watcher, extractor and dashboard components.")
    if recent_logs:
        for log in recent_logs:
            level     = str(log.get("level", "INFO")).upper()
            css_class = "log-info"
            if level == "WARNING":
                css_class = "log-warning"
            elif level == "ERROR":
                css_class = "log-error"
            st.markdown(
                f"""
                <div class="log-line {css_class}">
                    <div class="log-meta">{log.get("timestamp", "")} | {log.get("component", "").upper()} | {level}</div>
                    <div>{log.get("message", "")}</div>
                </div>
                """,
                unsafe_allow_html=True
            )
    else:
        empty_state("No Platform Logs", "Backend events will appear here after the pipeline starts.")


# ---------------------------------
# PAGE: LIVE MONITOR
# ---------------------------------

def render_live_monitor(db: DatabaseManager, table_limit: int) -> None:
    render_capture_config_warning(db)

    metrics              = db.get_summary_metrics()
    recent_logs          = db.get_recent_logs(limit=25)
    recent_events        = db.get_recent_events(limit=20)
    last_pcap            = db.get_last_processed_pcap()
    configured_interface = db.get_config("capture_interface", "") or ""

    section_header("Live Monitor", "Operational status of capture, watcher and JA3 processing pipeline.")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        badge = get_status_badge("Backend Online", "success")
        st.markdown(f'<div class="info-panel"><div class="info-title">Backend</div><div class="info-value">{badge}</div></div>', unsafe_allow_html=True)
    with c2:
        active = metrics.get("active_pcap_jobs", 0)
        badge  = get_status_badge("Watching / Processing" if active > 0 else "Idle / Waiting", "info" if active > 0 else "neutral")
        st.markdown(f'<div class="info-panel"><div class="info-title">Watcher Status</div><div class="info-value">{badge}</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="info-panel"><div class="info-title">Configured Interface</div><div class="info-value">{configured_interface or "Not Set"}</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="info-panel"><div class="info-title">Event Count</div><div class="info-value">{metrics.get("total_events", 0)}</div></div>', unsafe_allow_html=True)

    left, right = st.columns([1, 1])

    with left:
        section_header("Current Operational State")
        pcap_name = last_pcap["file_name"] if last_pcap else "No processed file yet"
        pcap_time = last_pcap["processed_at"] if last_pcap else "-"
        html = f"""
        <div class="section-card">
            <div class="status-grid">
                <div class="status-item">
                    <div class="status-item-label">Last Processed PCAP</div>
                    <div class="status-item-value">{pcap_name}</div>
                </div>
                <div class="status-item">
                    <div class="status-item-label">Last Processed At</div>
                    <div class="status-item-value">{pcap_time}</div>
                </div>
                <div class="status-item">
                    <div class="status-item-label">Known Events</div>
                    <div class="status-item-value">{metrics.get("known_events", 0)}</div>
                </div>
                <div class="status-item">
                    <div class="status-item-label">Unknown Events</div>
                    <div class="status-item-value">{metrics.get("unknown_events", 0)}</div>
                </div>
            </div>
        </div>
        """
        st.markdown(html, unsafe_allow_html=True)

        section_header("Recent Detections", "Most recent TLS records observed by the system.")
        if recent_events:
            df   = pd.DataFrame(recent_events)
            cols = [c for c in ["timestamp", "dst_ip", "dst_port", "ja3_hash", "prediction", "status"] if c in df.columns]
            st.dataframe(df[cols], use_container_width=True, hide_index=True)
        else:
            empty_state("No Detections Yet", "Run the backend with capture enabled or process a PCAP file to populate detections.")

    with right:
        section_header("Backend Activity Feed", "Most recent system actions across capture, watcher, extractor and dashboard.")
        if recent_logs:
            st.markdown('<div class="log-console">', unsafe_allow_html=True)
            for log in recent_logs:
                level     = str(log.get("level", "INFO")).upper()
                css_class = "log-info"
                if level == "WARNING":
                    css_class = "log-warning"
                elif level == "ERROR":
                    css_class = "log-error"
                st.markdown(
                    f"""
                    <div class="log-line {css_class}">
                        <div class="log-meta">{log.get("timestamp", "")} | {log.get("component", "").upper()} | {level}</div>
                        <div>{log.get("message", "")}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            empty_state("No Backend Logs", "System activity will appear here after the pipeline starts generating logs.")


# ---------------------------------
# PAGE: PCAP EXPLORER
# ---------------------------------

def render_pcap_explorer(db: DatabaseManager, table_limit: int) -> None:
    section_header("PCAP Explorer", "Track lifecycle and processing outcome of captured or imported PCAP files.")

    status_filter = st.selectbox(
        "PCAP Status Filter",
        options=["All", "detected", "processing", "processed", "no_tls_records", "error"],
        index=0
    )

    selected_status = None if status_filter == "All" else status_filter
    pcap_files      = db.get_pcap_files(limit=table_limit, status=selected_status)

    if pcap_files:
        df = pd.DataFrame(pcap_files)
        df["file_size_readable"] = df["file_size"].apply(format_file_size)

        cols = [c for c in [
            "file_name", "status", "file_size_readable", "first_seen",
            "processed_at", "records_extracted", "records_logged", "error_message"
        ] if c in df.columns]

        st.dataframe(df[cols], use_container_width=True, hide_index=True)

        section_header("File Detail View", "Expand an individual PCAP record for deeper context.")
        for item in pcap_files[:10]:
            with st.expander(f"{item.get('file_name', 'Unnamed File')} | status={item.get('status', '-')}", expanded=False):
                st.write(f"**Full Path:** {item.get('file_path', '-')}")
                st.write(f"**File Size:** {format_file_size(item.get('file_size'))}")
                st.write(f"**First Seen:** {item.get('first_seen', '-')}")
                st.write(f"**Processed At:** {item.get('processed_at', '-')}")
                st.write(f"**Extracted Records:** {item.get('records_extracted', 0)}")
                st.write(f"**Logged Records:** {item.get('records_logged', 0)}")
                st.write(f"**Error Message:** {item.get('error_message') or '-'}")
    else:
        empty_state("No PCAP Records", "Once the watcher detects files in the capture directory, they will appear here.")


# ---------------------------------
# PAGE: FINGERPRINT INTELLIGENCE
# ---------------------------------

def render_fingerprint_intelligence(db: DatabaseManager, table_limit: int) -> None:
    section_header("Fingerprint Intelligence", "Explore unique TLS fingerprints, predictions and protocol behavior patterns.")

    top_ja3         = db.get_top_ja3_hashes(limit=15)
    top_predictions = db.get_top_predictions(limit=15)
    unique_fps      = db.get_recent_unique_fingerprints(limit=table_limit)
    top_ports       = db.get_port_distribution(limit=12)

    top_left, top_right = st.columns(2)

    with top_left:
        section_header("Top JA3 Fingerprints")
        if top_ja3:
            df  = pd.DataFrame(top_ja3)
            fig = px.bar(df, x="ja3_hash", y="hit_count",
                         color_discrete_sequence=["#00ff41"])
            cyber_layout(fig, xaxis_title="JA3 Hash", yaxis_title="Hits")
            st.plotly_chart(fig, use_container_width=True)
        else:
            empty_state("No JA3 Data", "Fingerprint analytics will appear after TLS events are processed.")

    with top_right:
        section_header("Prediction Distribution")
        if top_predictions:
            df  = pd.DataFrame(top_predictions)
            fig = px.bar(df, x="prediction", y="hit_count",
                         color_discrete_sequence=["#ff00a0"])
            cyber_layout(fig, xaxis_title="", yaxis_title="Hits")
            st.plotly_chart(fig, use_container_width=True)
        else:
            empty_state("No Prediction Data", "Prediction analytics will appear once fingerprints are classified.")

    bottom_left, bottom_right = st.columns(2)

    with bottom_left:
        section_header("Destination Port Distribution")
        if top_ports:
            df  = pd.DataFrame(top_ports)
            fig = px.bar(df, x="dst_port", y="hit_count",
                         color_discrete_sequence=["#ffe600"])
            cyber_layout(fig, xaxis_title="Destination Port", yaxis_title="Hits")
            st.plotly_chart(fig, use_container_width=True)
        else:
            empty_state("No Port Analytics", "Port-level intelligence will appear here after event processing.")

    with bottom_right:
        section_header("Recent Unique Fingerprints")
        if unique_fps:
            df   = pd.DataFrame(unique_fps)
            cols = [c for c in ["ja3_hash", "latest_prediction", "latest_status", "occurrences", "last_seen"] if c in df.columns]
            st.dataframe(df[cols], use_container_width=True, hide_index=True)
        else:
            empty_state("No Unique Fingerprints", "Unique JA3 hashes will be summarized here.")


# ---------------------------------
# PAGE: WHITELIST
# ---------------------------------

def render_whitelist(db: DatabaseManager, table_limit: int) -> None:
    section_header("Whitelist Management", "Known JA3 signatures trusted or mapped by the platform.")

    whitelist = db.get_all_whitelist_entries()

    if whitelist:
        df = pd.DataFrame(whitelist)

        search_text = st.text_input("Search whitelist by app name or JA3 hash", "")
        if search_text:
            mask = (
                df["app_name"].astype(str).str.contains(search_text, case=False, na=False)
                | df["ja3_hash"].astype(str).str.contains(search_text, case=False, na=False)
            )
            df = df[mask]

        df   = df.head(table_limit)
        cols = [c for c in ["created_at", "app_name", "ja3_hash", "category", "confidence", "source", "notes"] if c in df.columns]
        st.dataframe(df[cols], use_container_width=True, hide_index=True)
    else:
        empty_state("Whitelist Is Empty", "You can seed demo entries from Settings or add mappings later through the database/API flow.")


# ---------------------------------
# PAGE: CANDIDATES
# ---------------------------------

def render_candidates(db: DatabaseManager, table_limit: int) -> None:
    section_header("Candidate Queue", "Unknown or inferred JA3 signatures awaiting stronger confidence or manual promotion.")

    candidates = db.get_candidates(limit=table_limit)

    if candidates:
        df = pd.DataFrame(candidates)

        min_conf = st.slider("Minimum confidence", 0, 100, 0)
        if "confidence" in df.columns:
            df = df[df["confidence"] >= min_conf]

        search_text = st.text_input("Search candidates by JA3 hash or predicted app", "")
        if search_text:
            mask = (
                df["ja3_hash"].astype(str).str.contains(search_text, case=False, na=False)
                | df["predicted_app"].astype(str).str.contains(search_text, case=False, na=False)
            )
            df = df[mask]

        cols = [c for c in ["last_seen", "ja3_hash", "predicted_app", "confidence", "seen_count", "promoted"] if c in df.columns]
        st.dataframe(df[cols], use_container_width=True, hide_index=True)
    else:
        empty_state("No Candidates", "Unknown fingerprints will appear here once the predictor creates candidate records.")


# ---------------------------------
# PAGE: SYSTEM CONSOLE
# ---------------------------------

def render_system_console(db: DatabaseManager, table_limit: int) -> None:
    section_header("System Console", "Operational backend logs from dashboard, capture, watcher, extractor and predictor components.")

    col1, col2 = st.columns(2)
    with col1:
        level = st.selectbox("Log Level", ["All", "INFO", "WARNING", "ERROR"], index=0)
    with col2:
        component = st.selectbox("Component", ["All", "system", "dashboard", "capture", "watcher", "extractor", "predictor"], index=0)

    log_level     = None if level == "All" else level
    log_component = None if component == "All" else component

    logs = db.get_recent_logs(limit=table_limit, level=log_level, component=log_component)

    if logs:
        st.markdown('<div class="log-console">', unsafe_allow_html=True)
        for log in logs:
            level     = str(log.get("level", "INFO")).upper()
            css_class = "log-info"
            if level == "WARNING":
                css_class = "log-warning"
            elif level == "ERROR":
                css_class = "log-error"
            st.markdown(
                f"""
                <div class="log-line {css_class}">
                    <div class="log-meta">{log.get("timestamp", "")} | {log.get("component", "").upper()} | {level}</div>
                    <div>{log.get("message", "")}</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        empty_state("No Logs Matched", "No logs matched the selected filters.")


# ---------------------------------
# PAGE: SETTINGS
# ---------------------------------

def render_settings(db: DatabaseManager) -> None:
    section_header("Settings & Capture Configuration", "Configure device-specific capture settings here. Saved values are stored in SQLite and reused on the next launch.")

    current             = get_current_config(db)
    detected_interfaces = get_detected_interfaces(db)
    interface_options   = [""] + [item["index"] for item in detected_interfaces]

    interface_label_map = {"": "(Not configured)"}
    for item in detected_interfaces:
        interface_label_map[item["index"]] = item["display"]

    current_interface = current["capture_interface"]
    default_index     = 0
    if current_interface in interface_options:
        default_index = interface_options.index(current_interface)

    st.markdown("### Capture Interface")
    if detected_interfaces:
        selected_interface = st.selectbox(
            "Detected Interfaces",
            options=interface_options,
            index=default_index,
            format_func=lambda x: interface_label_map.get(x, x)
        )
        detected_df = pd.DataFrame(detected_interfaces)
        st.dataframe(detected_df[["index", "label"]], use_container_width=True, hide_index=True)
    else:
        st.warning(
            "TShark ile interface listesi alınamadı. TShark yolu yanlış olabilir ya da cihazda kurulu olmayabilir. "
            "Yine de interface numarasını manuel girebilirsin."
        )
        selected_interface = current_interface

    manual_interface = st.text_input(
        "Manual Interface Override",
        value="",
        placeholder="Optional: enter interface manually only if needed",
        help="Bu alan opsiyoneldir. Boş bırakırsan dropdown seçimi kaydedilir. Sadece özel durumda manuel interface adı/numarası gir."
    )

    st.markdown("### Runtime Settings")
    col1, col2 = st.columns(2)

    with col1:
        tshark_path    = st.text_input("TShark Path", value=current["tshark_path"])
        capture_filter = st.text_input("Capture Filter", value=current["capture_filter"], placeholder='e.g. tcp port 443')
        poll_interval  = st.number_input("Poll Interval (sec)", min_value=1, max_value=120, value=current["poll_interval"], step=1)
        stable_seconds = st.number_input("Stable Seconds", min_value=1, max_value=120, value=current["stable_seconds"], step=1)

    with col2:
        ring_duration  = st.number_input("Ring Duration (sec)", min_value=5, max_value=3600, value=current["ring_duration"], step=5)
        ring_files     = st.number_input("Ring File Count", min_value=1, max_value=500, value=current["ring_files"], step=1)
        dashboard_port = st.number_input("Dashboard Port", min_value=1024, max_value=65535, value=current["dashboard_port"], step=1)

    st.markdown("### Current Configuration Summary")
    summary_html = f"""
    <div class="section-card">
        <div class="status-grid">
            <div class="status-item">
                <div class="status-item-label">Current Saved Interface</div>
                <div class="status-item-value">{current_interface or "Not Set"}</div>
            </div>
            <div class="status-item">
                <div class="status-item-label">Current TShark Path</div>
                <div class="status-item-value">{current["tshark_path"]}</div>
            </div>
            <div class="status-item">
                <div class="status-item-label">Ring Duration</div>
                <div class="status-item-value">{current["ring_duration"]}</div>
            </div>
            <div class="status-item">
                <div class="status-item-label">Ring Files</div>
                <div class="status-item-value">{current["ring_files"]}</div>
            </div>
        </div>
    </div>
    """
    st.markdown(summary_html, unsafe_allow_html=True)

    effective_interface = (manual_interface or "").strip()
    if not effective_interface:
        effective_interface = (selected_interface or "").strip()

    col_save, col_apply, col_demo = st.columns(3)

    config_payload = {
        "capture_interface": effective_interface,
        "tshark_path":       tshark_path.strip(),
        "capture_filter":    capture_filter.strip(),
        "ring_duration":     str(ring_duration),
        "ring_files":        str(ring_files),
        "poll_interval":     str(poll_interval),
        "stable_seconds":    str(stable_seconds),
        "dashboard_port":    str(dashboard_port),
    }

    with col_save:
        if st.button("Save Only", use_container_width=True, key="settings_save_only"):
            db.set_many_config(config_payload)
            st.success(f"Settings saved. Interface: {effective_interface or 'Not Set'}")
            st.rerun()

    with col_apply:
        if st.button("Save & Apply", use_container_width=True, key="settings_save_apply"):
            db.set_many_config(config_payload)
            st.success(
                "Settings saved. Host capture agent will detect the config change automatically within a few seconds."
            )
            st.rerun()

    with col_demo:
        if st.button("Seed Demo Whitelist", use_container_width=True, key="settings_seed_demo"):
            db.seed_sample_whitelist()
            st.success("Sample whitelist entries added.")

    st.info(
        "Notes: Interface numbering changes from device to device. "
        "This page is the right place to configure it once per device. "
        "Saved settings are reused automatically by the backend on the next start."
    )


# ---------------------------------
# MAIN
# ---------------------------------

def main() -> None:
    load_css()
    db = get_db()

    render_hero()

    sidebar_state = render_sidebar()
    page          = sidebar_state["page"]
    table_limit   = sidebar_state["table_limit"]

    if page == "Overview":
        render_overview(db, table_limit)
    elif page == "Live Monitor":
        render_live_monitor(db, table_limit)
    elif page == "PCAP Explorer":
        render_pcap_explorer(db, table_limit)
    elif page == "Fingerprint Intelligence":
        render_fingerprint_intelligence(db, table_limit)
    elif page == "Whitelist":
        render_whitelist(db, table_limit)
    elif page == "Candidates":
        render_candidates(db, table_limit)
    elif page == "System Console":
        render_system_console(db, table_limit)
    elif page == "Settings":
        render_settings(db)


if __name__ == "__main__":
    main()