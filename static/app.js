const $ = (id) => document.getElementById(id);

const dropzone = $('dropzone');
const fileInput = $('pcap-file');
const pickButton = $('pick-button');
const progress = $('progress');
const progressFill = $('progress-fill');
const progressLabel = $('progress-label');
const messages = $('messages');
const metaBox = $('meta');
const statsBox = $('stats');
const protocolPanel = $('protocols-panel');
const protocolList = $('protocol-list');
const browserBanner = $('browser-banner');
const svgWrapper = $('svg-wrapper');
const emptyState = $('empty-state');
const downloadButton = $('download-button');
const tablesPanel = $('tables-panel');

const MAX_MB = Number(document.body.dataset.maxMb) || 2048;
let busy = false;

/* ------------------------------------------------------------------ */
/* Messaggi                                                            */
/* ------------------------------------------------------------------ */
function showMessage(text, kind) {
  const div = document.createElement('div');
  div.className = `alert ${kind}`;
  div.textContent = text;
  messages.appendChild(div);
}

function clearMessages() {
  messages.replaceChildren();
}

function formatSize(bytes) {
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function initBrowserBanner() {
  const ua = navigator.userAgent;
  const isChrome = /Chrome\//.test(ua) && !/Edg\//.test(ua) && !/OPR\//.test(ua);

  if (isChrome) {
    browserBanner.hidden = false;
    browserBanner.className = 'browser-banner supported';
    browserBanner.textContent = '✅ Browser supportato: Chrome. Funzionalità ottimizzate per il caricamento e la visualizzazione del grafico.';
    return;
  }

  browserBanner.hidden = false;
  browserBanner.className = 'browser-banner warning';
  browserBanner.textContent = '⚠️ Browser consigliato: Chrome per la migliore compatibilità con il visualizzatore PCAP.';
}

initBrowserBanner();

/* ------------------------------------------------------------------ */
/* Selezione file: bottone, click sulla zona, drag & drop              */
/* ------------------------------------------------------------------ */
pickButton.addEventListener('click', (event) => {
  event.stopPropagation();
  fileInput.click();
});

fileInput.addEventListener('click', (event) => event.stopPropagation());
dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    fileInput.click();
  }
});

fileInput.addEventListener('change', () => {
  const file = fileInput.files && fileInput.files[0];
  if (file) uploadFile(file);
  fileInput.value = ''; // permette di ricaricare lo stesso file
});

['dragenter', 'dragover'].forEach((type) =>
  dropzone.addEventListener(type, (event) => {
    event.preventDefault();
    dropzone.classList.add('dragover');
  })
);
['dragleave', 'drop'].forEach((type) =>
  dropzone.addEventListener(type, (event) => {
    event.preventDefault();
    dropzone.classList.remove('dragover');
  })
);
dropzone.addEventListener('drop', (event) => {
  const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
  if (file) uploadFile(file);
});

// evita che il browser apra il file se viene rilasciato fuori dalla zona
['dragover', 'drop'].forEach((type) => window.addEventListener(type, (event) => event.preventDefault()));

/* ------------------------------------------------------------------ */
/* Upload (corpo grezzo della richiesta, nessun form multipart)        */
/* ------------------------------------------------------------------ */
function setBusy(value) {
  busy = value;
  pickButton.disabled = value;
  dropzone.style.opacity = value ? 0.6 : 1;
}

const UPLOAD_TIMEOUT_MS = 0; // nessun timeout client: PCAP grandi possono richiedere tempo

class UploadError extends Error {}

// Trasferimento binario raw: niente multipart, chunk, parsing form o buffer RAM.
// Il backend salva lo stream direttamente in /app/uploads e risponde 202.
function postFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/analyze');
    xhr.responseType = 'json';
    xhr.timeout = UPLOAD_TIMEOUT_MS;
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.setRequestHeader('X-Filename', encodeURIComponent(file.name));
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded, event.total);
    };
    xhr.onload = () => {
      const body = xhr.response || {};
      if (xhr.status >= 200 && xhr.status < 300) return resolve(body);
      reject(new UploadError(body.error || `Errore del server (HTTP ${xhr.status}).`));
    };
    xhr.onerror = () => reject(new UploadError('Connessione al server non riuscita durante il caricamento.'));
    xhr.ontimeout = () => reject(new UploadError('Timeout durante il caricamento del file.'));
    xhr.send(file);
  });
}

async function uploadFile(file) {
  if (busy) return;
  clearMessages();

  if (file.size === 0) {
    showMessage(`Il file "${file.name}" è vuoto (0 byte). Se è una cattura Wireshark ancora in corso, fermala e salvala prima.`, 'error');
    return;
  }
  if (file.size > MAX_MB * 1048576) {
    showMessage(`File troppo grande (${formatSize(file.size)}): il limite è ${MAX_MB} MB.`, 'error');
    return;
  }

  setBusy(true);
  progress.hidden = false;
  progress.classList.remove('indeterminate');
  progressFill.style.width = '0';
  progressLabel.textContent = `Caricamento di ${file.name} (${formatSize(file.size)})…`;

  try {
    const result = await postFile(file, (loaded, total) => {
      const pct = Math.min(100, Math.round((loaded / total) * 100));
      progressFill.style.width = `${pct}%`;
      progressLabel.textContent = `Caricamento: ${pct}% (${formatSize(Math.min(loaded, file.size))} di ${formatSize(file.size)})`;
    });
    if (!result || !result.job_id) throw new UploadError('Il server non ha restituito l’ID dell’analisi.');
    pollJob(result.job_id);
  } catch (err) {
    finish(() => showMessage(err.message || 'Invio non riuscito.', 'error'));
  }
}

function pollJob(jobId) {
  progress.classList.remove('indeterminate');
  progressFill.style.width = '0';
  progressLabel.textContent = 'Analisi in coda…';
  let failures = 0;

  const tick = async () => {
    let data;
    try {
      const response = await fetch(`/api/jobs/${jobId}`, { cache: 'no-store' });
      data = await response.json();
      failures = 0;
    } catch (err) {
      failures += 1;
      if (failures >= 6) {
        return finish(() => showMessage('Connessione al server persa durante l\'analisi.', 'error'));
      }
      return setTimeout(tick, 1000);
    }

    if (data.state === 'done') {
      progressFill.style.width = '100%';
      return finish(() => renderResult(data.result));
    }
    if (data.state === 'error') {
      return finish(() => showMessage(data.error || 'Analisi non riuscita.', 'error'));
    }

    const pct = data.percent || 0;
    progressFill.style.width = `${pct}%`;
    const packets = Number(data.packets || 0).toLocaleString('it-IT');
    progressLabel.textContent = data.state === 'queued'
      ? 'Analisi in coda…'
      : `Analisi: ${pct}% — ${packets} pacchetti letti (${data.elapsed}s)`;
    setTimeout(tick, 500);
  };
  tick();
}

function finish(callback) {
  progress.hidden = true;
  setBusy(false);
  callback();
}

/* ------------------------------------------------------------------ */
/* Rendering del risultato                                             */
/* ------------------------------------------------------------------ */
function stat(label, value) {
  const item = document.createElement('div');
  item.className = 'stat-item';
  const span = document.createElement('span');
  span.textContent = label;
  const strong = document.createElement('strong');
  strong.textContent = Number(value).toLocaleString('it-IT');
  item.append(span, strong);
  return item;
}

function getProtocolGraph(data, protocol) {
  if (!data || !data.protocol_graphs) return { nodes: [], edges: [], nodes_total: 0, svg: '' };
  if (protocol === 'all') {
    return {
      nodes: data.nodes || [],
      edges: data.edges || [],
      nodes_total: data.nodes_total || (data.nodes || []).length,
      svg: data.svg || '',
    };
  }
  return data.protocol_graphs[protocol] || { nodes: [], edges: [], nodes_total: 0, svg: '' };
}

function renderResult(data) {
  (data.notices || []).forEach((text) => showMessage(text, 'warn'));

  metaBox.hidden = false;
  metaBox.replaceChildren();
  const label = document.createElement('span');
  label.textContent = 'File: ';
  const name = document.createElement('strong');
  name.textContent = `${data.file_name} (${formatSize(data.size)})`;
  metaBox.append(label, name);

  statsBox.hidden = false;
  statsBox.replaceChildren(
    stat('IP unici', data.unique_ips),
    stat('Pacchetti IP', data.ip_packets),
    stat('Pacchetti totali', data.total_packets),
    stat('Non-IP (ARP…)', data.non_ip_packets)
  );

  const protocols = Array.isArray(data.protocols) ? data.protocols : [];
  protocolList.replaceChildren();

  const allOption = document.createElement('option');
  allOption.value = 'all';
  allOption.textContent = 'ALL';
  protocolList.appendChild(allOption);

  protocols.forEach(({ name, count }) => {
    const option = document.createElement('option');
    option.value = name;
    option.textContent = `${name.toUpperCase()} (${count})`;
    protocolList.appendChild(option);
  });

  protocolList.value = 'all';
  protocolPanel.hidden = protocols.length === 0;
  protocolList.onchange = () => {
    const selected = protocolList.value || 'all';
    applyProtocolFilter(data, selected);
  };

  applyProtocolFilter(data, 'all');
}

function applyProtocolFilter(data, selectedProtocol) {
  const graph = getProtocolGraph(data, selectedProtocol);
  svgWrapper.innerHTML = graph.svg || '';
  svgWrapper.hidden = false;
  emptyState.hidden = true;
  downloadButton.disabled = false;
  resetView();

  const list = $('ip-list');
  list.replaceChildren();
  (graph.nodes || []).forEach((ip) => {
    const pill = document.createElement('span');
    pill.className = 'pill';
    pill.textContent = ip;
    list.appendChild(pill);
  });
  if ((graph.nodes_total || 0) > (graph.nodes || []).length) {
    const more = document.createElement('span');
    more.className = 'pill';
    more.textContent = `+${(graph.nodes_total || 0) - (graph.nodes || []).length} altri`;
    list.appendChild(more);
  }

  const rows = $('edge-rows');
  rows.replaceChildren();
  (graph.edges || []).forEach((edge) => {
    const tr = document.createElement('tr');
    [edge.source, edge.target, edge.weight].forEach((value) => {
      const td = document.createElement('td');
      td.textContent = value;
      tr.appendChild(td);
    });
    rows.appendChild(tr);
  });
  tablesPanel.hidden = (graph.nodes || []).length === 0;
}

/* ------------------------------------------------------------------ */
/* Zoom / pan / download del grafico                                   */
/* ------------------------------------------------------------------ */
let scale = 1;
let currentX = 0;
let currentY = 0;
let isDragging = false;
let dragStartX = 0;
let dragStartY = 0;

const currentSvg = () => svgWrapper.querySelector('svg');

function applyTransform() {
  const svg = currentSvg();
  if (svg) svg.style.transform = `translate(${currentX}px, ${currentY}px) scale(${scale})`;
}

function resetView() {
  scale = 1;
  currentX = 0;
  currentY = 0;
  applyTransform();
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

// zoom mantenendo fermo il punto (px, py), in coordinate del contenitore
function zoomAt(newScale, px, py) {
  newScale = clamp(newScale, 0.3, 8);
  const ratio = newScale / scale;
  currentX = px - (px - currentX) * ratio;
  currentY = py - (py - currentY) * ratio;
  scale = newScale;
  applyTransform();
}

function downloadSvg() {
  const svg = currentSvg();
  if (!svg) return;
  const clone = svg.cloneNode(true);
  const [, , w, h] = clone.getAttribute('viewBox').split(/\s+/);
  clone.setAttribute('width', w);
  clone.setAttribute('height', h);
  clone.removeAttribute('style');
  const source = '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(clone);
  const blob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'ip-graph.svg';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

document.querySelectorAll('[data-action]').forEach((button) => {
  button.addEventListener('click', () => {
    const action = button.dataset.action;
    const r = svgWrapper.getBoundingClientRect();
    if (action === 'zoom-in') zoomAt(scale * 1.25, r.width / 2, r.height / 2);
    if (action === 'zoom-out') zoomAt(scale / 1.25, r.width / 2, r.height / 2);
    if (action === 'reset') resetView();
    if (action === 'download') downloadSvg();
  });
});

svgWrapper.addEventListener('wheel', (event) => {
  event.preventDefault();
  const r = svgWrapper.getBoundingClientRect();
  zoomAt(scale * (event.deltaY < 0 ? 1.12 : 1 / 1.12), event.clientX - r.left, event.clientY - r.top);
}, { passive: false });

svgWrapper.addEventListener('pointerdown', (event) => {
  isDragging = true;
  dragStartX = event.clientX - currentX;
  dragStartY = event.clientY - currentY;
  svgWrapper.setPointerCapture(event.pointerId);
});

svgWrapper.addEventListener('pointermove', (event) => {
  if (!isDragging) return;
  currentX = event.clientX - dragStartX;
  currentY = event.clientY - dragStartY;
  applyTransform();
});

const stopDrag = () => { isDragging = false; };
svgWrapper.addEventListener('pointerup', stopDrag);
svgWrapper.addEventListener('pointercancel', stopDrag);
