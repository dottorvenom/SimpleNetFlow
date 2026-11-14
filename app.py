from __future__ import annotations

import logging
import math
import os
import shutil
import tempfile
import threading
import time
import uuid
from collections import Counter, OrderedDict
from html import escape

from urllib.parse import unquote

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from pcap_parser import PcapParseError, format_ip, parse_capture

app = Flask(__name__)
app.logger.setLevel(logging.INFO)  # visibili in `docker compose logs`

# Dimensione massima dell'upload (MB). Configurabile con MAX_UPLOAD_MB.
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "2048"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
UPLOAD_DIR = os.getenv("UPLOAD_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Per file grandi (2 GB o piu') i limiti grafici devono essere disattivati
# di default, cosi' il grafo puo' mostrare tutti gli IP rilevati.
MAX_GRAPH_NODES = int(os.getenv("MAX_GRAPH_NODES", "0"))
MAX_GRAPH_EDGES = int(os.getenv("MAX_GRAPH_EDGES", "0"))
MAX_PILLS = 300
# 0 = nessun limite, utile per catture grandi che richiedono tutti gli IP.
MAX_TRACKED_PAIRS = int(os.getenv("MAX_TRACKED_PAIRS", "0"))

# Le analisi girano in background: la UI interroga lo stato con il progresso.
JOBS: dict = {}
JOBS_LOCK = threading.Lock()
JOB_TTL_SECONDS = 30 * 60
ANALYSIS_SLOTS = threading.BoundedSemaphore(int(os.getenv("MAX_PARALLEL_ANALYSES", "2")))


def build_graph(edge_counter):
    """edge_counter: Counter {(src, dst): n_pacchetti} -> {"nodes", "edges"}."""
    seen_nodes = OrderedDict()
    clean = Counter()

    for (source, target), weight in edge_counter.items():
        if not source or not target or source == target:
            continue
        seen_nodes.setdefault(source, None)
        seen_nodes.setdefault(target, None)
        clean[(source, target)] += weight

    edges = [
        {"source": s, "target": t, "weight": w}
        for (s, t), w in sorted(clean.items(), key=lambda i: (-i[1], i[0][0], i[0][1]))
    ]
    return {"nodes": list(seen_nodes.keys()), "edges": edges}


def build_ip_edges(ip_pairs):
    """Compatibilita': accetta una lista di coppie (src, dst), anche ripetute."""
    return build_graph(Counter(ip_pairs))


def limit_graph(graph, max_nodes, max_edges):
    """Riduce il grafo da disegnare solo quando e' esplicitamente richiesto.

    Con max_nodes/max_edges pari a 0 o negativi il grafo viene mostrato completo,
    necessario per catture grandi come 2 GB senza perdere IP nel diagramma.
    """
    nodes = graph["nodes"]
    edges = graph["edges"]
    hidden_nodes = 0

    if max_nodes is not None and max_nodes > 0 and len(nodes) > max_nodes:
        volume = Counter()
        for edge in edges:
            volume[edge["source"]] += edge["weight"]
            volume[edge["target"]] += edge["weight"]
        keep = {n for n, _ in volume.most_common(max_nodes)}
        hidden_nodes = len(nodes) - len(keep)
        nodes = [n for n in nodes if n in keep]
        edges = [e for e in edges if e["source"] in keep and e["target"] in keep]

    if max_edges is not None and max_edges > 0:
        hidden_edges = max(0, len(edges) - max_edges)
        edges = edges[:max_edges]
    else:
        hidden_edges = 0

    return {"nodes": nodes, "edges": edges}, hidden_nodes, hidden_edges


def generate_svg_graph(graph_data, width=1400, height=1000):
    nodes = graph_data.get("nodes") or []
    edges = graph_data.get("edges") or []

    if not nodes:
        return (
            f'<svg id="network-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="100%" height="100%">'
            f'<rect width="100%" height="100%" fill="#0b1020"/>'
            f'<text x="{width / 2}" y="{height / 2}" text-anchor="middle" fill="#dfe7ff" '
            f'font-size="24" font-family="Arial">Nessun dato disponibile</text></svg>'
        )

    count = len(nodes)
    center_x, center_y = width / 2, height / 2
    radius = min(width, height) * 0.32
    rotate_labels = count > 24

    volume = Counter()
    for edge in edges:
        volume[edge["source"]] += edge["weight"]
        volume[edge["target"]] += edge["weight"]
    max_volume = max(volume.values(), default=1)
    max_weight = max((e["weight"] for e in edges), default=1)

    max_r = max(2.5, min(18.0, math.pi * radius / count * 0.9))
    min_r = max(1.5, max_r * 0.35)
    dense = len(edges) > 200

    positions, radii, angles = {}, {}, {}
    for index, node in enumerate(nodes):
        angle = (2 * math.pi * index) / count - math.pi / 2
        angles[node] = angle
        positions[node] = (
            center_x + radius * math.cos(angle),
            center_y + radius * math.sin(angle),
        )
        radii[node] = min_r + (max_r - min_r) * math.sqrt(volume.get(node, 0) / max_volume)

    svg = [
        f'<svg id="network-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="100%" preserveAspectRatio="xMidYMid meet">',
        "<defs>"
        '<marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto" markerUnits="userSpaceOnUse">'
        '<path d="M0,0 L0,6 L8,3 z" fill="#8dd3ff"/></marker></defs>',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#0b1020"/>',
    ]

    for edge in edges:
        s, t = edge["source"], edge["target"]
        if s not in positions or t not in positions:
            continue
        x1, y1 = positions[s]
        x2, y2 = positions[t]
        dx, dy = x2 - x1, y2 - y1
        dist = math.hypot(dx, dy) or 1.0
        # accorcia la linea ai bordi dei cerchi, cosi' la freccia resta visibile
        x1 += dx / dist * radii[s]
        y1 += dy / dist * radii[s]
        x2 -= dx / dist * (radii[t] + 2)
        y2 -= dy / dist * (radii[t] + 2)
        ratio = edge["weight"] / max_weight
        svg.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#8dd3ff" '
            f'stroke-width="{(0.5 if dense else 0.8) + ratio * (2.5 if dense else 4):.2f}" '
            f'stroke-opacity="{(0.08 + ratio * 0.5) if dense else (0.18 + ratio * 0.7):.2f}" '
            f'marker-end="url(#arrow)"><title>{escape(s)} → {escape(t)}: {edge["weight"]} pacchetti</title></line>'
        )

    for node in nodes:
        x, y = positions[node]
        r = radii[node]
        angle = angles[node]
        cos_a = math.cos(angle)
        label_r = r + 8
        lx = x + math.cos(angle) * label_r
        ly = y + math.sin(angle) * label_r
        anchor = "start" if cos_a >= 0 else "end"

        if rotate_labels:
            deg = math.degrees(angle)
            if cos_a < 0:
                deg += 180
            text = (
                f'<text x="{lx:.1f}" y="{ly:.1f}" fill="#dfe7ff" font-size="11" font-family="Arial" '
                f'text-anchor="{anchor}" dominant-baseline="middle" '
                f'transform="rotate({deg:.1f} {lx:.1f} {ly:.1f})">{escape(node)}</text>'
            )
        else:
            text = (
                f'<text x="{lx:.1f}" y="{ly + 4:.1f}" fill="#dfe7ff" font-size="13" font-family="Arial" '
                f'text-anchor="{anchor}">{escape(node)}</text>'
            )

        svg.append(
            f'<g><circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="#1fa6ff" fill-opacity="0.9" '
            f'stroke="#dfe7ff" stroke-width="1.2"><title>{escape(node)}: {volume.get(node, 0)} pacchetti</title></circle>'
            f"{text}</g>"
        )

    svg.append("</svg>")
    return "\n".join(svg)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", max_upload_mb=MAX_UPLOAD_MB)


def save_request_file(tmp_path):
    """Scrive il body HTTP direttamente su disco senza bufferizzare il PCAP in RAM.

    La UI invia application/octet-stream con Content-Length e X-Filename.
    Il supporto multipart resta disponibile per client esterni/test.
    """
    content_type = (request.content_type or "").lower()
    if content_type.startswith("multipart/"):
        uploaded = next((f for f in request.files.values() if f and f.filename), None)
        if uploaded is None:
            return "", 0
        uploaded.save(tmp_path)
        return uploaded.filename, os.path.getsize(tmp_path)

    name = unquote(request.headers.get("X-Filename", "")) or "capture.pcap"
    name = os.path.basename(name.replace("\\", "/"))[:255] or "capture.pcap"
    expected = request.content_length
    if expected is None:
        raise ValueError("Content-Length assente: il server richiede un upload con lunghezza dichiarata.")
    if expected <= 0:
        return name, 0
    max_len = app.config.get("MAX_CONTENT_LENGTH")
    if max_len is not None and expected > max_len:
        raise ValueError(f"File troppo grande: il limite e' {max_len} byte.")
    if expected > MAX_UPLOAD_MB * 1024 * 1024:
        raise ValueError(f"File troppo grande: limite {MAX_UPLOAD_MB} MB.")

    # Leggiamo il flusso WSGI con dimensione esplicita. A differenza del parser
    # multipart e di request.get_data(), questo evita di interpretare il PCAP
    # come form e non accumula l'intero body in memoria.
    stream = request.environ["wsgi.input"]
    remaining = expected
    written = 0
    with open(tmp_path, "wb", buffering=1024 * 1024) as out:
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError(
                    f"Upload interrotto: ricevuti {written} byte su {expected}."
                )
            out.write(chunk)
            written += len(chunk)
            remaining -= len(chunk)
    out_size = os.path.getsize(tmp_path)
    if out_size != expected:
        raise ValueError(f"Dimensione salvata non coerente: {out_size} byte su {expected}.")
    return name, out_size


def build_result(file_name, size, stats):
    """Trasforma le statistiche del parser nel JSON mostrato dalla UI."""
    names = {}
    pairs = Counter()
    for (raw_src, raw_dst), weight in stats.pairs.items():
        src = names.get(raw_src) or names.setdefault(raw_src, format_ip(raw_src))
        dst = names.get(raw_dst) or names.setdefault(raw_dst, format_ip(raw_dst))
        pairs[(src, dst)] += weight

    graph = build_graph(pairs)
    notices = []

    if stats.truncated:
        notices.append("Il file risulta troncato o corrotto: e' stata analizzata solo la parte leggibile.")
    if stats.dropped_packets:
        notices.append(
            f"Il file contiene moltissime coppie di IP diverse: ne sono state tracciate al massimo "
            f"{MAX_TRACKED_PAIRS:,} e {stats.dropped_packets:,} pacchetti con coppie nuove non sono "
            "nel grafico (aumenta MAX_TRACKED_PAIRS se serve)."
        )
    if not graph["nodes"]:
        notices.append("Nessun pacchetto IP trovato nel file (solo traffico non-IP come ARP/STP?).")

    shown, hidden_nodes, hidden_edges = limit_graph(graph, MAX_GRAPH_NODES, MAX_GRAPH_EDGES)
    if hidden_nodes or hidden_edges:
        notices.append(
            f"Per restare leggibile il grafico mostra {len(shown['nodes'])} IP su {len(graph['nodes'])} "
            f"(i piu' attivi) e {len(shown['edges'])} connessioni su {len(graph['edges'])} (le piu' "
            "frequenti). L'elenco e le tabelle contengono tutti i dati."
        )

    protocol_rows = [
        {"name": name, "count": count}
        for name, count in sorted(stats.protocols.items(), key=lambda item: (-item[1], item[0]))
    ]

    protocol_graphs = {"all": {"nodes": graph["nodes"][:MAX_PILLS],
                              "nodes_total": len(graph["nodes"]),
                              "edges": graph["edges"][:25],
                              "svg": generate_svg_graph(shown)}}
    for proto in stats.protocol_pairs:
        convert = Counter()
        for (src_raw, dst_raw), weight in stats.protocol_pairs[proto].items():
            src = format_ip(src_raw)
            dst = format_ip(dst_raw)
            convert[(src, dst)] += weight
        filtered = build_graph(convert)
        filtered_shown, _, _ = limit_graph(filtered, MAX_GRAPH_NODES, MAX_GRAPH_EDGES)
        protocol_graphs[proto] = {
            "nodes": filtered_shown["nodes"][:MAX_PILLS],
            "nodes_total": len(filtered["nodes"]),
            "edges": filtered_shown["edges"][:25],
            "svg": generate_svg_graph(filtered_shown),
        }

    return dict(
        file_name=file_name,
        size=size,
        svg=generate_svg_graph(shown),
        nodes=graph["nodes"][:MAX_PILLS],
        nodes_total=len(graph["nodes"]),
        edges=graph["edges"][:25],
        unique_ips=len(graph["nodes"]),
        ip_packets=stats.ip_packets,
        total_packets=stats.packets,
        non_ip_packets=stats.non_ip,
        protocols=protocol_rows,
        protocol_graphs=protocol_graphs,
        notices=notices,
    )


def prune_jobs():
    now = time.time()
    with JOBS_LOCK:
        for job_id in [k for k, j in JOBS.items() if now - j["created"] > JOB_TTL_SECONDS]:
            del JOBS[job_id]


def run_job(job_id, tmp_path):
    job = JOBS[job_id]

    def on_progress(bytes_read, packets):
        job["packets"] = packets
        if job["size"]:
            job["percent"] = min(99, int(bytes_read * 100 / job["size"]))

    try:
        job["state"] = "queued"
        with ANALYSIS_SLOTS:
            job["state"] = "running"
            job["started"] = time.time()
            app.logger.info("Analisi avviata: %r (%d byte)", job["file_name"], job["size"])
            stats = parse_capture(tmp_path, progress=on_progress, max_pairs=MAX_TRACKED_PAIRS)
            job["packets"] = stats.packets
            job["percent"] = 99
            job["result"] = build_result(job["file_name"], job["size"], stats)
        job["state"] = "done"
        job["percent"] = 100
        app.logger.info("Analisi completata: %r in %.1fs (%d pacchetti)",
                        job["file_name"], time.time() - job["started"], job["packets"])
    except PcapParseError as exc:
        job["error"] = str(exc)
        job["state"] = "error"
        app.logger.info("Analisi fallita: %r: %s", job["file_name"], exc)
    except Exception as exc:  # pragma: no cover - rete di sicurezza per la UI
        app.logger.exception("Errore inatteso nell'analisi")
        job["error"] = f"Errore inatteso nell'analisi: {exc}"
        job["state"] = "error"
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass


def start_job(tmp_path, file_name, size):
    job_id = uuid.uuid4().hex
    JOBS[job_id] = dict(
        state="queued", file_name=file_name, size=size, percent=0, packets=0,
        created=time.time(), started=None, result=None, error=None,
    )
    threading.Thread(target=run_job, args=(job_id, tmp_path), daemon=True).start()
    return job_id


# ---------------------------------------------------------------------------
# Upload a blocchi (resistente a stalli e connessioni lente)
# ---------------------------------------------------------------------------
UPLOADS: dict = {}
UPLOAD_CHUNK = int(os.getenv("UPLOAD_CHUNK_MB", "1")) * 1024 * 1024
UPLOAD_TTL_SECONDS = 60 * 60
UPLOADS_LOCK = threading.Lock()


def prune_uploads():
    now = time.time()
    expired = []
    with UPLOADS_LOCK:
        for upload_id, item in list(UPLOADS.items()):
            if now - item["last"] > UPLOAD_TTL_SECONDS:
                expired.append(UPLOADS.pop(upload_id))
    for item in expired:
        try:
            os.unlink(item["path"])
        except FileNotFoundError:
            pass


@app.route("/api/uploads", methods=["POST"])
def upload_start():
    prune_uploads()
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "capture")[:255]
    try:
        size = int(body.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    if size <= 0:
        return jsonify(error="File vuoto o dimensione non valida."), 400
    if size > MAX_UPLOAD_MB * 1024 * 1024:
        return jsonify(error=f"File troppo grande: il limite e' {MAX_UPLOAD_MB} MB (variabile MAX_UPLOAD_MB)."), 413
    free_bytes = shutil.disk_usage(UPLOAD_DIR).free
    if size > free_bytes:
        return jsonify(error=f"Spazio insufficiente nel container: servono {size} byte, disponibili {free_bytes}."), 507

    fd, path = tempfile.mkstemp(suffix=".cap", dir=UPLOAD_DIR)
    os.close(fd)
    upload_id = uuid.uuid4().hex
    with UPLOADS_LOCK:
        UPLOADS[upload_id] = dict(path=path, name=name, size=size, received=0, logged=0,
                                  last=time.time(), lock=threading.Lock())
    app.logger.info("Upload iniziato: %r (%d byte)", name, size)
    return jsonify(upload_id=upload_id, chunk_size=UPLOAD_CHUNK)


@app.route("/api/uploads/<upload_id>/chunk", methods=["PUT"])
def upload_chunk(upload_id):
    with UPLOADS_LOCK:
        up = UPLOADS.get(upload_id)
    if up is None:
        return jsonify(error="Upload non trovato: il server e' stato riavviato o l'upload e' scaduto. Ricarica il file."), 404

    offset = request.args.get("offset", type=int)
    content_length = request.content_length
    if content_length is not None and content_length > UPLOAD_CHUNK + 64 * 1024:
        return jsonify(error=f"Blocco troppo grande: massimo {UPLOAD_CHUNK // (1024 * 1024)} MB."), 413

    # Il client invia blocchi piccoli (1 MB): il buffering e' quindi limitato
    # e permette di gestire in modo sicuro i retry anche parzialmente sovrapposti.
    data = request.get_data(cache=False)
    with up["lock"]:
        if offset is None or offset < 0 or offset > up["received"]:
            return jsonify(error="Offset non valido.", received=up["received"]), 409

        if offset < up["received"]:
            overlap = up["received"] - offset
            if overlap >= len(data):
                up["last"] = time.time()
                return jsonify(received=up["received"])
            data = data[overlap:]

        remaining = up["size"] - up["received"]
        if len(data) > remaining:
            app.logger.warning("Chunk oltre la dimensione dichiarata per %s: %d byte extra ignorati",
                               upload_id, len(data) - remaining)
            data = data[:remaining]

        if data:
            with open(up["path"], "ab") as out:
                out.write(data)
            up["received"] += len(data)

        up["last"] = time.time()
        if up["received"] - up["logged"] >= 64 * 1024 * 1024:
            up["logged"] = up["received"]
            app.logger.info("Upload %r: %d/%d MB", up["name"], up["received"] >> 20, up["size"] >> 20)
        return jsonify(received=up["received"])


@app.route("/api/uploads/<upload_id>/finish", methods=["POST"])
def upload_finish(upload_id):
    up = UPLOADS.get(upload_id)
    if up is None:
        return jsonify(error="Upload non trovato: il server e' stato riavviato o l'upload e' scaduto. Ricarica il file."), 404
    with up["lock"]:
        if up["received"] != up["size"]:
            return jsonify(error=f"Upload incompleto: ricevuti {up['received']} byte su {up['size']}.",
                           received=up["received"]), 409
    with UPLOADS_LOCK:
        actual_size = os.path.getsize(up["path"])
    if actual_size != up["size"]:
        return jsonify(error=f"File salvato incompleto: {actual_size} byte su {up['size']}.", received=actual_size), 409
    with UPLOADS_LOCK:
        UPLOADS.pop(upload_id, None)
    app.logger.info("Upload completato nel container: %r (%d byte, %s)", up["name"], up["size"], up["path"])
    job_id = start_job(up["path"], up["name"], up["size"])
    return jsonify(job_id=job_id, file_name=up["name"], size=up["size"]), 202


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Riceve il file e avvia l'analisi in background. Risponde subito con job_id."""
    prune_jobs()
    fd, tmp_path = tempfile.mkstemp(prefix="pcap-", suffix=".cap", dir=UPLOAD_DIR)
    os.close(fd)

    app.logger.info("Richiesta upload ricevuta: content_type=%r content_length=%r",
                    request.content_type, request.content_length)
    try:
        file_name, size = save_request_file(tmp_path)
        if size == 0:
            raise ValueError("Il server non ha ricevuto dati: file vuoto.")
        app.logger.info("Upload salvato nel container: %r (%d byte, %s)", file_name, size, tmp_path)
    except ValueError as exc:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        app.logger.warning("Upload rifiutato: %s", exc)
        status = 413 if "troppo grande" in str(exc).lower() else 400
        return jsonify(error=str(exc)), status
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        app.logger.exception("Errore durante la ricezione del PCAP")
        raise

    job_id = start_job(tmp_path, file_name, size)
    return jsonify(job_id=job_id, file_name=file_name, size=size), 202


@app.route("/api/jobs/<job_id>", methods=["GET"])
def job_status(job_id):
    job = JOBS.get(job_id)
    if job is None:
        return jsonify(state="error",
                       error="Analisi non trovata: il server e' stato riavviato o l'analisi e' scaduta. Ricarica il file."), 404

    body = dict(
        state=job["state"],
        percent=job["percent"],
        packets=job["packets"],
        elapsed=round(time.time() - (job["started"] or job["created"]), 1),
    )
    if job["state"] == "done":
        body["result"] = job["result"]
    elif job["state"] == "error":
        body["error"] = job["error"]
        body["file_name"] = job["file_name"]
    return jsonify(body)


@app.route("/health", methods=["GET"])
def health():
    usage = shutil.disk_usage(UPLOAD_DIR)
    return jsonify(status="ok", upload_dir=UPLOAD_DIR, free_bytes=usage.free), 200


@app.errorhandler(400)
def bad_request(error):
    # Werkzeug normalmente restituisce solo HTTP 400 nel log accessi.
    # Registriamo la causa e i metadati della richiesta per diagnosticare
    # eventuali body troncati o richieste malformate.
    app.logger.warning(
        "Richiesta HTTP 400: %s | %s %s | content_type=%r content_length=%r",
        getattr(error, "description", str(error)), request.method, request.path,
        request.content_type, request.content_length,
    )
    return jsonify(error="Richiesta HTTP non valida: controlla il formato del file inviato. "
                         "Dettaglio registrato nei log del container."), 400


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error=f"File troppo grande: il limite e' {MAX_UPLOAD_MB} MB (variabile MAX_UPLOAD_MB)."), 413


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    port = int(os.getenv("PORT", "9977"))
    app.run(host="0.0.0.0", port=port, debug=debug_mode, threaded=True)
