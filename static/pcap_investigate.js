
(function () {
    'use strict';

    var state = {
        viewer: null,
        modal: null,
        brief: null,
        tab: 'brief',
        busy: false,
        error: '',
        timelineFilter: 'all',
        graphType: 'all',
        graphAll: false,
        graphZoom: 1,
        graphPanX: 0,
        graphPanY: 0,
        graphDrag: null,
        narrative: null,
        narrativeBusy: false,
        narrativeError: '',
        runToken: 0,
        applied: null
    };

    var TYPE_COLOR = {
        host: '#6cb6ff',
        domain: '#c297ff',
        port: '#fbbf24',
        protocol: '#5fd4c9',
        mac: '#f08fa3',
        service: '#34d399'
    };

    var EDGE_COLOR = {
        conversation: '#6cb6ff',
        name: '#c297ff',
        protocol: '#5fd4c9',
        service: '#34d399',
        link: '#f08fa3'
    };

    var TYPE_LABEL = {
        host: 'Host',
        domain: 'Domain',
        port: 'Port',
        protocol: 'Protocol',
        mac: 'MAC',
        service: 'Service'
    };

    function api() {
        return window.PcapViewerApi || null;
    }

    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function attr(value) {
        return esc(value);
    }

    function clip(value, max) {
        var text = String(value == null ? '' : value);
        return text.length > max ? text.slice(0, Math.max(0, max - 1)) + '…' : text;
    }

    function plural(count, one, many) {
        var n = Number(count) || 0;
        return n + ' ' + (n === 1 ? one : (many || one + 's'));
    }

    function fmtBytes(bytes) {
        var n = Number(bytes);
        if (!isFinite(n) || n < 0) return '-';
        if (n < 1024) return Math.round(n) + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10 * 1024 ? 2 : 1) + ' KB';
        if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(2) + ' MB';
        return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }

    function fmtSeconds(seconds) {
        var s = Math.max(0, Number(seconds) || 0);
        if (s < 0.001) return Math.round(s * 1000000) + ' us';
        if (s < 1) return Math.round(s * 1000) + ' ms';
        if (s < 60) return (Math.round(s * 10) / 10) + ' s';
        if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.round(s % 60) + 's';
        return Math.floor(s / 3600) + 'h ' + Math.round((s % 3600) / 60) + 'm';
    }

    function sanitizeDashes(text) {
        return String(text == null ? '' : text)
            .replace(/[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/g, '-');
    }

    function severityLabel(value) {
        return value === 'high' ? 'High' : value === 'medium' ? 'Medium'
            : value === 'low' ? 'Low' : 'Info';
    }

    function severityBadge(value) {
        var severity = ['high', 'medium', 'low', 'info'].indexOf(value) >= 0 ? value : 'info';
        return '<span class="pcap-inv-sev ' + severity + '">' + severityLabel(severity) + '</span>';
    }

    function sourceLabel(value) {
        return value === 'case' ? 'Pinned case finding' : value === 'case-ref' ? 'Case packet reference' : 'Local finding';
    }

    function fileStem(name) {
        var value = String(name || 'capture').replace(/\.[A-Za-z0-9]+$/, '');
        value = value.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
        return value || 'capture';
    }

    function formatStamp(date) {
        try {
            var d = date instanceof Date ? date : new Date(date);
            return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
        } catch (e) {
            return new Date().toISOString();
        }
    }

    function formatClock(seconds) {
        var s = Math.max(0, Number(seconds) || 0);
        var h = Math.floor(s / 3600);
        var m = Math.floor((s % 3600) / 60);
        var rest = s % 60;
        var restText = rest < 10 ? '0' + rest.toFixed(3) : rest.toFixed(3);
        return (h ? h + ':' : '') + (m < 10 ? '0' + m : m) + ':' + restText;
    }

    function toast(text) {
        if (api() && api().toast) api().toast(text);
    }

    function copyText(text) {
        var value = String(text == null ? '' : text);
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(value).then(function () {
                toast('Copied to the clipboard.');
            }).catch(function () {
                fallbackCopy(value);
            });
            return;
        }
        fallbackCopy(value);
    }

    function fallbackCopy(text) {
        var area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try { document.execCommand('copy'); toast('Copied to the clipboard.'); } catch (e) { }
        area.remove();
    }

    function download(filename, text, type) {
        var blob = new Blob([text], { type: type || 'text/plain' });
        var url = URL.createObjectURL(blob);
        var link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    function entityEntries(entities) {
        var out = [];
        if (!entities) return out;
        var maps = [
            { key: 'hosts', type: 'host' },
            { key: 'domains', type: 'domain' },
            { key: 'macs', type: 'mac' },
            { key: 'ports', type: 'port' },
            { key: 'protocols', type: 'protocol' },
            { key: 'services', type: 'service' }
        ];
        for (var m = 0; m < maps.length; m++) {
            var values = entities[maps[m].key];
            if (!values) continue;
            if (!Array.isArray(values)) values = [values];
            for (var i = 0; i < values.length; i++) {
                if (values[i] == null || values[i] === '') continue;
                out.push({ type: maps[m].type, value: String(values[i]) });
            }
        }
        return out;
    }

    function entityFilter(type, value) {
        if (window.PcapTriage && typeof window.PcapTriage.entityFilter === 'function') {
            return window.PcapTriage.entityFilter(type, value);
        }
        return '';
    }

    // ------------------------------------------------------------------
    // Modal shell
    // ------------------------------------------------------------------

    function open() {
        var viewerApi = api();
        if (!viewerApi) {
            return false;
        }
        var viewer = viewerApi.active();
        if (!viewer || !viewer.packets || !viewer.packets.length) {
            toast('Load a capture before opening the investigation workspace.');
            return false;
        }
        if (!window.PcapTriage || typeof window.PcapTriage.brief !== 'function') {
            toast('The local triage engine is unavailable.');
            return false;
        }

        state.viewer = viewer;
        state.brief = null;
        state.tab = 'brief';
        state.busy = true;
        state.error = '';
        state.timelineFilter = 'all';
        state.graphType = 'all';
        state.graphAll = false;
        state.graphZoom = 1;
        state.graphPanX = 0;
        state.graphPanY = 0;
        state.graphDrag = null;
        state.narrative = null;
        state.narrativeBusy = false;
        state.narrativeError = '';
        state.applied = null;
        state.runToken++;

        var modal = viewerApi.openDialog('Investigation Brief', shell(viewer), {
            wide: true,
            className: 'pcap-inv-modal'
        });
        if (!modal) {
            state.viewer = null;
            return false;
        }
        state.viewer = viewer;
        state.modal = modal;
        state.brief = null;
        state.busy = true;
        state.error = '';
        state.runToken++;
        state.modal.onClose(function () {
            state.runToken++;
            state.modal = null;
            state.viewer = null;
            state.brief = null;
            state.narrative = null;
            state.applied = null;
        });
        bindShell(modal.root);
        render();
        runAnalysis();
        return true;
    }

    function shell(viewer) {
        return '<div class="pcap-inv" data-inv-root>' +
            '<div class="pcap-inv-head">' +
                '<div class="pcap-inv-headline">' +
                    '<div class="pcap-inv-kicker">Evidence ledger investigation</div>' +
                    '<h3 data-inv-capture>' + esc(viewer.name || 'capture') + '</h3>' +
                    '<p data-inv-meta>Local detectors are running.</p>' +
                '</div>' +
                '<div class="pcap-inv-head-actions">' +
                    '<button type="button" class="pcap-btn" data-inv-refresh>Rescan</button>' +
                    '<button type="button" class="pcap-btn" data-inv-export-md>Markdown</button>' +
                    '<button type="button" class="pcap-btn" data-inv-export-html>HTML</button>' +
                    '<button type="button" class="pcap-btn" data-inv-copy>Copy brief</button>' +
                '</div>' +
            '</div>' +
            '<div class="pcap-inv-applied" data-inv-applied hidden></div>' +
            '<div class="pcap-inv-tabs" role="tablist" aria-label="Investigation views">' +
                '<button type="button" class="pcap-inv-tab active" role="tab" aria-selected="true" data-inv-tab="brief">Brief <span data-inv-count-brief>0</span></button>' +
                '<button type="button" class="pcap-inv-tab" role="tab" aria-selected="false" data-inv-tab="timeline">Timeline <span data-inv-count-timeline>0</span></button>' +
                '<button type="button" class="pcap-inv-tab" role="tab" aria-selected="false" data-inv-tab="graph">Entity graph <span data-inv-count-graph>0</span></button>' +
            '</div>' +
            '<div class="pcap-inv-panel" data-inv-panel></div>' +
        '</div>';
    }

    function bindShell(root) {
        root.addEventListener('click', function (event) {
            var tab = event.target.closest('[data-inv-tab]');
            if (tab) {
                state.tab = tab.getAttribute('data-inv-tab');
                render();
                return;
            }
            var timelineFilter = event.target.closest('[data-inv-tl-filter]');
            if (timelineFilter) {
                state.timelineFilter = timelineFilter.getAttribute('data-inv-tl-filter');
                render();
                return;
            }
            var frame = event.target.closest('[data-inv-frame]');
            if (frame) {
                jumpToFrame(parseInt(frame.getAttribute('data-inv-frame'), 10));
                return;
            }
            var packetRef = event.target.closest('[data-ai-packet]');
            if (packetRef) {
                jumpToFrame(parseInt(packetRef.getAttribute('data-ai-packet'), 10));
                return;
            }
            var zoom = event.target.closest('[data-inv-zoom]');
            if (zoom) {
                var zoomAction = zoom.getAttribute('data-inv-zoom');
                if (zoomAction === 'reset') resetGraphZoom();
                else graphZoomAt(null, null, zoomAction === 'in' ? 1.25 : 0.8);
                return;
            }
            var filter = event.target.closest('[data-inv-filter]');
            if (filter) {
                applyExpr(filter.getAttribute('data-inv-filter'));
                return;
            }
            var copyFilter = event.target.closest('[data-inv-copy-filter]');
            if (copyFilter) {
                copyText(copyFilter.getAttribute('data-inv-copy-filter'));
                return;
            }
            if (event.target.closest('[data-inv-refresh]')) {
                runAnalysis();
                return;
            }
            if (event.target.closest('[data-inv-export-md]')) {
                exportBrief('md');
                return;
            }
            if (event.target.closest('[data-inv-export-html]')) {
                exportBrief('html');
                return;
            }
            if (event.target.closest('[data-inv-copy]')) {
                if (!state.brief) { toast('Generate the brief first.'); return; }
                copyText(briefMarkdown(state.brief, state.narrative));
                return;
            }
            if (event.target.closest('[data-inv-narrative]')) {
                generateNarrative();
                return;
            }
            if (event.target.closest('[data-inv-ai-settings]')) {
                openAISettings();
                return;
            }
            if (event.target.closest('[data-inv-applied-close]')) {
                closeApplied();
                return;
            }
            if (event.target.closest('[data-inv-graph-all]')) {
                state.graphAll = true;
                resetGraphZoomState();
                render();
                return;
            }
            if (event.target.closest('[data-inv-graph-top]')) {
                state.graphAll = false;
                resetGraphZoomState();
                render();
                return;
            }
        });

        root.addEventListener('change', function (event) {
            if (event.target.matches('[data-inv-graph-type]')) {
                state.graphType = event.target.value || 'all';
                state.graphAll = false;
                resetGraphZoomState();
                render();
            }
        });

        root.addEventListener('wheel', function (event) {
            if (!event.target || !event.target.closest) return;
            var canvas = event.target.closest('.pcap-inv-graph-canvas');
            if (!canvas || event.target.closest('.pcap-inv-zoom')) return;
            var svg = canvas.querySelector('.pcap-inv-svg');
            if (!svg) return;
            if (state.graphZoom <= 1.001 && event.deltaY > 0) return;
            event.preventDefault();
            var point = graphPoint(svg, event.clientX, event.clientY);
            graphZoomAt(point.x, point.y, event.deltaY < 0 ? 1.16 : 1 / 1.16);
        }, { passive: false });

        root.addEventListener('pointerdown', function (event) {
            if (event.button != null && event.button !== 0) return;
            if (!event.target || !event.target.closest) return;
            var canvas = event.target.closest('.pcap-inv-graph-canvas');
            if (!canvas || state.graphZoom <= 1.001) return;
            if (event.target.closest('.pcap-inv-zoom') ||
                event.target.closest('.pcap-inv-node-group') ||
                event.target.closest('.pcap-inv-edge-group')) return;
            var svg = canvas.querySelector('.pcap-inv-svg');
            if (!svg) return;
            var point = graphPoint(svg, event.clientX, event.clientY);
            state.graphDrag = {
                pointerId: event.pointerId,
                startX: point.x,
                startY: point.y,
                panX: state.graphPanX,
                panY: state.graphPanY
            };
            svg.classList.add('pcap-inv-panning');
            if (svg.setPointerCapture) {
                try { svg.setPointerCapture(event.pointerId); } catch (err) { }
            }
            event.preventDefault();
        });

        root.addEventListener('pointermove', function (event) {
            if (!state.graphDrag) return;
            var svg = graphSvg();
            if (!svg) {
                state.graphDrag = null;
                return;
            }
            var point = graphPoint(svg, event.clientX, event.clientY);
            state.graphPanX = state.graphDrag.panX + point.x - state.graphDrag.startX;
            state.graphPanY = state.graphDrag.panY + point.y - state.graphDrag.startY;
            clampGraphPan();
            applyGraphZoom();
            event.preventDefault();
        });

        function endGraphPan(event) {
            if (!state.graphDrag) return;
            var svg = graphSvg();
            if (svg) {
                svg.classList.remove('pcap-inv-panning');
                if (svg.releasePointerCapture && event && event.pointerId != null) {
                    try { svg.releasePointerCapture(event.pointerId); } catch (err) { }
                }
            }
            state.graphDrag = null;
        }

        root.addEventListener('pointerup', endGraphPan);
        root.addEventListener('pointercancel', endGraphPan);

        root.addEventListener('keydown', function (event) {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            var filter = event.target.closest('[data-inv-filter]');
            if (!filter || filter.tagName === 'BUTTON') return;
            event.preventDefault();
            applyExpr(filter.getAttribute('data-inv-filter'));
        });
    }

    function panel() {
        return state.modal && state.modal.root ? state.modal.root.querySelector('[data-inv-panel]') : null;
    }

    function runAnalysis() {
        if (!state.viewer || !state.modal) return;
        var viewer = state.viewer;
        var token = ++state.runToken;
        resetGraphZoomState();
        state.busy = true;
        state.error = '';
        state.brief = null;
        state.narrative = null;
        state.narrativeError = '';
        state.applied = null;
        render();
        setTimeout(function () {
            if (token !== state.runToken || !state.modal) return;
            try {
                var brief = window.PcapTriage.brief(viewer);
                if (token !== state.runToken || !state.modal) return;
                state.brief = brief;
                state.busy = false;
                render();
            } catch (err) {
                if (token !== state.runToken || !state.modal) return;
                state.busy = false;
                state.error = err && err.message ? err.message : String(err);
                render();
            }
        }, 30);
    }

    function render() {
        if (!state.modal) return;
        var root = state.modal.root;
        var body = state.modal.body;
        var scrollTop = body ? body.scrollTop : 0;
        var brief = state.brief;
        var viewer = state.viewer;
        var capture = root.querySelector('[data-inv-capture]');
        var meta = root.querySelector('[data-inv-meta]');
        if (capture) capture.textContent = brief ? brief.capture : (viewer ? viewer.name : 'capture');
        if (meta) {
            if (state.busy) {
                meta.textContent = 'Scanning packets locally and building the evidence ledger.';
            } else if (brief) {
                meta.textContent = plural(brief.stats.packets, 'packet') + ' · ' +
                    fmtBytes(brief.stats.bytes) + ' · ' + fmtSeconds(brief.stats.duration) + ' · ' +
                    plural(brief.ledger.length, 'active finding') + ' · ' +
                    plural(brief.timeline.length, 'timeline event') + ' · ' +
                    plural(brief.graph.totalNodes, 'entity', 'entities') + ' · generated ' + formatStamp(brief.generatedAt);
            } else {
                meta.textContent = viewer ? viewer.name : 'capture';
            }
        }

        var counts = {
            brief: brief ? brief.ledger.length : 0,
            timeline: brief ? brief.timeline.length : 0,
            graph: brief ? brief.graph.totalNodes : 0
        };
        var briefCount = root.querySelector('[data-inv-count-brief]');
        var timelineCount = root.querySelector('[data-inv-count-timeline]');
        var graphCount = root.querySelector('[data-inv-count-graph]');
        if (briefCount) briefCount.textContent = counts.brief;
        if (timelineCount) timelineCount.textContent = counts.timeline;
        if (graphCount) graphCount.textContent = counts.graph;

        var tabs = root.querySelectorAll('[data-inv-tab]');
        for (var t = 0; t < tabs.length; t++) {
            var active = tabs[t].getAttribute('data-inv-tab') === state.tab;
            tabs[t].classList.toggle('active', active);
            tabs[t].setAttribute('aria-selected', active ? 'true' : 'false');
        }

        renderApplied();
        var host = panel();
        if (!host) return;
        if (state.busy) {
            host.innerHTML = '<div class="pcap-inv-loading">' +
                '<div class="pcap-inv-spinner" aria-hidden="true"></div>' +
                '<strong>Building the evidence ledger</strong>' +
                '<p>Running deterministic detectors, indexing packets, linking entities and folding in the local case file. Nothing leaves this tab.</p>' +
            '</div>';
        } else if (state.error) {
            host.innerHTML = '<div class="pcap-inv-empty pcap-inv-error">' +
                '<strong>The brief could not be built.</strong>' +
                '<p>' + esc(state.error) + '</p>' +
                '<button type="button" class="pcap-btn primary" data-inv-refresh>Try again</button>' +
            '</div>';
        } else if (!brief) {
            host.innerHTML = '<div class="pcap-inv-empty">No brief is available.</div>';
        } else if (state.tab === 'timeline') {
            host.innerHTML = timelineMarkup(brief);
        } else if (state.tab === 'graph') {
            host.innerHTML = graphMarkup(brief);
            applyGraphZoom();
        } else {
            host.innerHTML = briefMarkup(brief);
        }
        if (body) body.scrollTop = scrollTop;
    }

    function renderApplied() {
        if (!state.modal) return;
        var strip = state.modal.root.querySelector('[data-inv-applied]');
        if (!strip) return;
        if (!state.applied) {
            strip.hidden = true;
            strip.innerHTML = '';
            return;
        }
        strip.hidden = false;
        strip.innerHTML = '<span class="pcap-inv-applied-dot"></span>' +
            '<span><strong>Filter applied.</strong> ' + plural(state.applied.total, 'packet') +
            ' match. Close this workspace to inspect them.</span>' +
            '<code>' + esc(clip(state.applied.expr, 140)) + '</code>' +
            '<button type="button" class="pcap-btn" data-inv-applied-close>Close and inspect</button>';
    }

    function jumpToFrame(no) {
        if (!isFinite(no) || no < 0) return;
        if (!api().selectNo(no)) {
            toast('Frame #' + no + ' is not present in this capture.');
            return;
        }
        if (state.modal) state.modal.close();
        toast('Selected frame #' + no + '.');
    }

    function applyExpr(expr) {
        var text = String(expr == null ? '' : expr).trim();
        if (!text) return false;
        var result = api().queryPackets(text, 1);
        if (result.error) {
            toast('Filter error: ' + result.error);
            return false;
        }
        var ok = api().setFilter(text);
        if (!ok) {
            toast('The filter could not be applied.');
            return false;
        }
        state.applied = { expr: text, total: result.total };
        renderApplied();
        toast('Filter applied: ' + plural(result.total, 'packet') + ' match.');
        return true;
    }

    function closeApplied() {
        var applied = state.applied;
        if (applied) {
            var result = api().queryPackets(applied.expr, 1);
            if (!result.error && result.nos.length) api().selectNo(result.nos[0]);
        }
        if (state.modal) state.modal.close();
    }

    function openAISettings() {
        if (!window.PcapAI) {
            toast('AI settings are unavailable.');
            return;
        }
        toast('Configure a provider, then reopen the assistant.');
        window.PcapAI.settings();
    }

    function aiReady() {
        return !!(window.PcapAI && typeof window.PcapAI.isConfigured === 'function' && window.PcapAI.isConfigured());
    }

    // ------------------------------------------------------------------
    // Brief
    // ------------------------------------------------------------------

    function frameChips(item, limit) {
        var frames = item.citations && item.citations.length ? item.citations : (item.frames || []).map(function (no) {
            return { no: no, label: 'Frame' };
        });
        if (!frames.length) {
            return '<span class="pcap-inv-uncited">No frame reference attached</span>';
        }
        var max = limit || frames.length;
        var html = '<span class="pcap-inv-frames">';
        for (var i = 0; i < frames.length && i < max; i++) {
            html += '<button type="button" class="pcap-inv-frame" data-inv-frame="' + Number(frames[i].no) +
                '" title="Jump to frame #' + Number(frames[i].no) + '">#' + Number(frames[i].no) + '</button>';
        }
        if (frames.length > max) {
            html += '<span class="pcap-inv-more">+' + (frames.length - max) + ' more</span>';
        }
        html += '</span>';
        return html;
    }

    function entityChips(item) {
        var entries = entityEntries(item.entities);
        if (!entries.length) return '';
        var html = '<div class="pcap-inv-entities">';
        for (var i = 0; i < entries.length && i < 18; i++) {
            var filter = entityFilter(entries[i].type, entries[i].value);
            html += '<button type="button" class="pcap-inv-entity ' + entries[i].type + '"' +
                (filter ? ' data-inv-filter="' + attr(filter) + '" title="Filter by this entity"' : '') + '>' +
                '<span>' + esc(TYPE_LABEL[entries[i].type] || entries[i].type) + '</span>' +
                esc(clip(entries[i].value, 42)) +
            '</button>';
        }
        html += '</div>';
        return html;
    }

    function ledgerMarkup(item, index) {
        var citations = item.citations || [];
        var rows = '';
        for (var i = 0; i < citations.length && i < 20; i++) {
            rows += '<button type="button" class="pcap-inv-citation" data-inv-frame="' + Number(citations[i].no) + '">' +
                '<span class="pcap-inv-citation-no">#' + Number(citations[i].no) + '</span>' +
                '<span>' + esc(citations[i].label || 'Packet') + '</span>' +
                '<span class="pcap-inv-citation-time">' + (citations[i].time == null ? '' : '+' + fmtSeconds(citations[i].time)) + '</span>' +
            '</button>';
        }
        if (citations.length > 20) {
            rows += '<div class="pcap-inv-detail-note">' + (citations.length - 20) + ' more cited frames are in the filter.</div>';
        }
        var filter = item.filter || '';
        return '<article class="pcap-inv-ledger ' + item.severity + '" data-inv-ledger="' + esc(item.id) + '">' +
            '<div class="pcap-inv-ledger-head">' +
                '<span class="pcap-inv-rank">' + String(index + 1).padStart(2, '0') + '</span>' +
                '<div class="pcap-inv-ledger-title">' +
                    '<div class="pcap-inv-ledger-titleline"><strong>' + esc(item.title) + '</strong>' +
                        severityBadge(item.severity) +
                        '<span class="pcap-inv-source">' + esc(item.source === 'case' ? 'Pinned' : 'Local') + '</span>' +
                    '</div>' +
                    '<div class="pcap-inv-ledger-meta">' + esc(item.detectorLabel) + ' · ' + item.confidence +
                        '% confidence · ' + plural(item.frames.length, 'frame') +
                        (item.missingFrames && item.missingFrames.length ? ' · ' + item.missingFrames.length + ' missing' : '') +
                    '</div>' +
                '</div>' +
            '</div>' +
            '<p class="pcap-inv-ledger-summary">' + esc(item.summary || item.detail || 'No summary supplied.') + '</p>' +
            '<div class="pcap-inv-ledger-frames">' + frameChips(item, 24) + '</div>' +
            (filter ? '<div class="pcap-inv-code-row">' +
                '<code class="pcap-inv-code">' + esc(filter) + '</code>' +
                '<button type="button" class="pcap-btn" data-inv-filter="' + attr(filter) + '">Apply</button>' +
                '<button type="button" class="pcap-btn" data-inv-copy-filter="' + attr(filter) + '">Copy</button>' +
            '</div>' : '<div class="pcap-inv-detail-note">No display filter is attached to this finding.</div>') +
            '<details class="pcap-inv-details">' +
                '<summary>Evidence, entities and next pivot</summary>' +
                (item.detail ? '<p>' + esc(item.detail) + '</p>' : '') +
                (item.note ? '<p class="pcap-inv-note">Analyst note: ' + esc(item.note) + '</p>' : '') +
                (rows ? '<div class="pcap-inv-citations">' + rows + '</div>' : '<p class="pcap-inv-detail-note">No cited frames were supplied.</p>') +
                (item.missingFrames && item.missingFrames.length ?
                    '<p class="pcap-inv-warning">Missing frames: ' + item.missingFrames.map(function (no) { return '#' + no; }).join(', ') + '</p>' : '') +
                entityChips(item) +
                (item.nextPivot ? '<div class="pcap-inv-next"><span>Next pivot</span><p>' + esc(item.nextPivot) + '</p></div>' : '') +
            '</details>' +
        '</article>';
    }

    function briefMarkup(brief) {
        var ledger = brief.ledger || [];
        var hypotheses = brief.hypotheses || [];
        var html = '<div class="pcap-inv-brief">';

        html += '<section class="pcap-inv-card pcap-inv-overview">' +
            '<div class="pcap-inv-section-head"><div><span class="pcap-inv-kicker">Assessment</span><h4>What the local evidence says</h4></div>' +
                '<span class="pcap-inv-integrity ' + (brief.integrity.uncited ? 'warn' : 'ok') + '">' +
                    (brief.integrity.uncited ? brief.integrity.uncited + ' uncited' : 'Every claim cited') +
                '</span>' +
            '</div>' +
            '<ul class="pcap-inv-overview-list">';
        for (var o = 0; o < brief.overview.length; o++) {
            html += '<li>' + esc(brief.overview[o]) + '</li>';
        }
        html += '</ul>' +
            '<div class="pcap-inv-integrity-row">' +
                '<span><strong>' + brief.integrity.claims + '</strong> claims</span>' +
                '<span><strong>' + brief.integrity.cited + '</strong> cited</span>' +
                '<span><strong>' + brief.integrity.uncited + '</strong> uncited</span>' +
                '<span><strong>' + brief.integrity.missingFrames + '</strong> missing frames</span>' +
                '<span><strong>' + brief.stats.detectorErrors.length + '</strong> detector errors</span>' +
            '</div>' +
            (brief.stats.detectorErrors.length ? '<details class="pcap-inv-details"><summary>Detector errors</summary>' +
                brief.stats.detectorErrors.map(function (item) {
                    return '<p><code>' + esc(item.detector) + '</code> ' + esc(item.error) + '</p>';
                }).join('') + '</details>' : '') +
        '</section>';

        html += '<section class="pcap-inv-card">' +
            '<div class="pcap-inv-section-head"><div><span class="pcap-inv-kicker">Ranked locally</span><h4>Hypotheses to validate</h4></div>' +
                '<span class="pcap-inv-hint">Deterministic detectors, not AI</span></div>';
        if (!hypotheses.length) {
            html += '<div class="pcap-inv-empty-small">No hypotheses were generated.</div>';
        } else {
            for (var h = 0; h < hypotheses.length; h++) {
                var item = hypotheses[h];
                html += '<article class="pcap-inv-hypothesis ' + item.severity + '">' +
                    '<div class="pcap-inv-hyp-head">' +
                        '<span class="pcap-inv-hyp-rank">' + item.rank + '</span>' +
                        '<strong>' + esc(item.title) + '</strong>' +
                        severityBadge(item.severity) +
                        '<span class="pcap-inv-confidence">' + item.confidence + '%</span>' +
                    '</div>' +
                    '<p>' + esc(item.statement) + '</p>' +
                    '<div class="pcap-inv-hyp-foot">' + frameChips(item, 10) +
                        (item.filter ? '<button type="button" class="pcap-btn" data-inv-filter="' + attr(item.filter) + '">Apply filter</button>' : '') +
                    '</div>' +
                '</article>';
            }
        }
        html += '</section>';

        html += '<section class="pcap-inv-card">' +
            '<div class="pcap-inv-section-head"><div><span class="pcap-inv-kicker">Evidence ledger</span><h4>Claims, frames and next pivots</h4></div>' +
                '<span class="pcap-inv-hint">' + plural(ledger.length, 'entry') + '</span></div>';
        if (!ledger.length) {
            html += '<div class="pcap-inv-empty-small">No active local finding and no pinned finding for this capture. That is not proof that the traffic is benign.</div>';
        } else {
            for (var l = 0; l < ledger.length; l++) html += ledgerMarkup(ledger[l], l);
        }
        html += '</section>';

        html += '<section class="pcap-inv-card">' +
            '<div class="pcap-inv-section-head"><div><span class="pcap-inv-kicker">Next actions</span><h4>What to do with this evidence</h4></div></div>' +
            '<ol class="pcap-inv-actions">';
        for (var r = 0; r < brief.recommendations.length; r++) {
            html += '<li>' + esc(brief.recommendations[r]) + '</li>';
        }
        html += '</ol></section>';

        html += '<section class="pcap-inv-card pcap-inv-case">' +
            '<div class="pcap-inv-section-head"><div><span class="pcap-inv-kicker">Case context</span><h4>' + esc(brief.case.name) + '</h4></div>' +
                '<span class="pcap-inv-hint">' + brief.case.pinned + ' pinned · ' + brief.case.refs + ' packet refs</span></div>' +
            '<div class="pcap-inv-case-body">' +
                (brief.case.notes ? '<p class="pcap-inv-case-notes">' + esc(brief.case.notes) + '</p>' :
                    '<p class="pcap-inv-detail-note">No case notes yet. Record scope, decisions and the reason for each conclusion.</p>') +
            '</div>' +
        '</section>';

        html += narrativeMarkup(brief);
        html += '</div>';
        return html;
    }

    function narrativeMarkup(brief) {
        var ready = aiReady();
        var html = '<section class="pcap-inv-card pcap-inv-narrative">' +
            '<div class="pcap-inv-section-head"><div><span class="pcap-inv-kicker">AI explanation</span><h4>Narrative over the evidence ledger</h4></div>' +
                '<span class="pcap-inv-ai-badge">explains, never detects</span></div>' +
            '<p class="pcap-inv-narrative-intro">The AI receives the local brief above. It must cite frames from the ledger and is not allowed to add findings. Check the citation result before using the narrative in a report.</p>';
        if (!ready) {
            html += '<div class="pcap-inv-ai-empty">' +
                '<p>No model provider is configured. The local brief, timeline, entity graph and exports work without AI. Add a provider to generate the explanatory narrative.</p>' +
                '<button type="button" class="pcap-btn primary" data-inv-ai-settings>Open AI settings</button>' +
            '</div></div>';
            return html;
        }
        html += '<div class="pcap-inv-narrative-actions">' +
            '<button type="button" class="pcap-btn primary" data-inv-narrative' + (state.narrativeBusy ? ' disabled' : '') + '>' +
                (state.narrativeBusy ? 'Writing narrative…' : state.narrative ? 'Regenerate narrative' : 'Generate AI narrative') +
            '</button>' +
            (state.narrative ? '<span class="pcap-inv-hint">Model: ' + esc(state.narrative.model || 'configured provider') + '</span>' : '') +
        '</div>';
        if (state.narrativeBusy) {
            html += '<div class="pcap-inv-narrative-loading"><div class="pcap-inv-spinner small" aria-hidden="true"></div> The model is reading the evidence ledger.</div>';
        } else if (state.narrativeError) {
            html += '<div class="pcap-inv-warning">' + esc(state.narrativeError) + '</div>';
        } else if (state.narrative) {
            var check = citationCheck(state.narrative.text, brief);
            html += '<div class="pcap-inv-citation-check ' + (check.bad || check.outside ? 'warn' : 'ok') + '">' +
                '<strong>Citation check</strong> ' +
                plural(check.total, 'frame reference') + ' · ' +
                check.connected + ' in the ledger · ' +
                check.outside + ' outside the ledger · ' +
                check.missing + ' not in this capture' +
            '</div>';
            var render = window.PcapAI && typeof window.PcapAI.renderMarkdown === 'function' ?
                window.PcapAI.renderMarkdown(sanitizeDashes(state.narrative.text)) :
                '<pre>' + esc(sanitizeDashes(state.narrative.text)) + '</pre>';
            html += '<div class="pcap-inv-narrative-body">' + render + '</div>';
            html += '<div class="pcap-inv-detail-note">The narrative is an explanation, not independent detection. Every claim above remains anchored to the local ledger.</div>';
        } else {
            html += '<div class="pcap-inv-ai-empty"><p>Generate a reviewer-facing narrative with frame citations. The local ledger remains the source of truth.</p></div>';
        }
        html += '</section>';
        return html;
    }

    function generateNarrative() {
        if (!state.brief || state.narrativeBusy) return;
        if (!aiReady()) {
            state.narrativeError = 'Add an API key in AI settings, or point the base URL at a local model.';
            state.narrativeBusy = false;
            render();
            return;
        }
        var token = state.runToken;
        state.narrativeBusy = true;
        state.narrativeError = '';
        render();
        window.PcapAI.investigationNarrative(state.brief, { viewer: state.viewer }).then(function (result) {
            if (token !== state.runToken || !state.modal) return;
            state.narrative = result;
            state.narrativeBusy = false;
            state.narrativeError = '';
            render();
        }).catch(function (err) {
            if (token !== state.runToken || !state.modal) return;
            state.narrativeBusy = false;
            state.narrativeError = err && err.message ? err.message : String(err);
            render();
        });
    }

    function citationCheck(text, brief) {
        var valid = {};
        var ledger = brief.ledger || [];
        for (var i = 0; i < ledger.length; i++) {
            var frames = ledger[i].frames || [];
            for (var f = 0; f < frames.length; f++) valid[Number(frames[f])] = true;
        }
        var all = {};
        if (state.viewer && state.viewer.packets) {
            for (var p = 0; p < state.viewer.packets.length; p++) all[Number(state.viewer.packets[p].no)] = true;
        }
        var seen = {};
        var references = [];
        var source = sanitizeDashes(text);
        var regex = /#(\d{1,7})/g;
        var match;
        while ((match = regex.exec(source))) {
            var no = Number(match[1]);
            if (!isFinite(no) || seen[no]) continue;
            seen[no] = true;
            references.push(no);
        }
        var connected = 0;
        var outside = 0;
        var missing = 0;
        for (var r = 0; r < references.length; r++) {
            if (!all[references[r]]) missing++;
            else if (valid[references[r]]) connected++;
            else outside++;
        }
        return {
            total: references.length,
            connected: connected,
            outside: outside,
            missing: missing,
            bad: missing > 0,
            references: references
        };
    }

    // ------------------------------------------------------------------
    // Timeline
    // ------------------------------------------------------------------

    function timelineTypes() {
        return [
            { key: 'all', label: 'All' },
            { key: 'high', label: 'High' },
            { key: 'medium', label: 'Medium' },
            { key: 'low', label: 'Low' },
            { key: 'info', label: 'Info' },
            { key: 'case', label: 'Case' }
        ];
    }

    function timelineMatches(event, filter) {
        if (filter === 'all') return true;
        if (filter === 'case') return event.source === 'case' || event.source === 'case-ref';
        return event.severity === filter;
    }

    function timelineMarkup(brief) {
        var events = brief.timeline || [];
        var filtered = events.filter(function (event) { return timelineMatches(event, state.timelineFilter); });
        var html = '<div class="pcap-inv-timeline">' +
            '<div class="pcap-inv-toolbar">' +
                '<div class="pcap-inv-chips" role="group" aria-label="Timeline filter">';
        var types = timelineTypes();
        var counts = {};
        for (var c = 0; c < types.length; c++) {
            counts[types[c].key] = events.filter(function (event) { return timelineMatches(event, types[c].key); }).length;
        }
        for (var t = 0; t < types.length; t++) {
            html += '<button type="button" class="pcap-inv-chip' + (state.timelineFilter === types[t].key ? ' active' : '') +
                '" data-inv-tl-filter="' + types[t].key + '">' + esc(types[t].label) +
                ' <span>' + counts[types[t].key] + '</span></button>';
        }
        html += '</div><span class="pcap-inv-hint">' + plural(filtered.length, 'event') +
            ' · every active finding and pinned case item is kept</span></div>';

        if (!filtered.length) {
            html += '<div class="pcap-inv-empty-small">No timeline events match this filter.</div></div>';
            return html;
        }
        html += '<div class="pcap-inv-axis">';
        var lastTime = null;
        for (var e = 0; e < filtered.length; e++) {
            var event = filtered[e];
            var timeLabel = event.rel != null ? '+' + fmtSeconds(event.rel) :
                event.at != null ? formatClock(event.at) : 'unknown time';
            var gap = '';
            if (lastTime != null && event.rel != null) {
                var delta = event.rel - lastTime;
                if (delta > 0.001) gap = '<span class="pcap-inv-gap">+' + fmtSeconds(delta) + ' since previous</span>';
            }
            if (event.rel != null) lastTime = event.rel;
            html += '<div class="pcap-inv-event ' + event.severity + (event.present ? '' : ' missing') +
                '" data-inv-frame="' + Number(event.no) + '" role="button" tabindex="0" title="Select frame #' + Number(event.no) + '">' +
                '<div class="pcap-inv-event-time">' + esc(timeLabel) + '</div>' +
                '<div class="pcap-inv-event-pin"><span></span></div>' +
                '<div class="pcap-inv-event-body">' +
                    '<div class="pcap-inv-event-title">' + esc(event.title) + severityBadge(event.severity) +
                        '<span class="pcap-inv-source">' + esc(sourceLabel(event.source)) + '</span></div>' +
                    '<div class="pcap-inv-event-meta">' +
                        (event.present ? '<button type="button" class="pcap-inv-frame" data-inv-frame="' + Number(event.no) + '">#' + Number(event.no) + '</button>' :
                            '<span class="pcap-inv-warning-inline">Frame #' + Number(event.no) + ' is not in this capture</span>') +
                        (event.capture ? ' · ' + esc(event.capture) : '') +
                        gap +
                    '</div>' +
                    (event.detail ? '<p>' + esc(clip(event.detail, 320)) + '</p>' : '') +
                '</div>' +
            '</div>';
        }
        html += '</div></div>';
        return html;
    }

    // ------------------------------------------------------------------
    // Entity graph
    // ------------------------------------------------------------------

    function graphView(brief) {
        var graph = brief.graph;
        var nodes = graph.nodes || [];
        if (state.graphType !== 'all') {
            nodes = nodes.filter(function (node) { return node.type === state.graphType; });
        }
        var nodeLimit = state.graphAll ? nodes.length : (state.graphType === 'all' ? 72 : 120);
        var shownNodes = nodes.slice(0, nodeLimit);
        var ids = {};
        for (var n = 0; n < shownNodes.length; n++) ids[shownNodes[n].key] = true;
        var edgeLimit = state.graphAll ? graph.edges.length : (state.graphType === 'all' ? 140 : 240);
        var shownEdges = (graph.edges || []).filter(function (edge) {
            return ids[edge.a] && ids[edge.b];
        }).slice(0, edgeLimit);
        return {
            nodes: shownNodes,
            edges: shownEdges,
            nodeTotal: nodes.length,
            edgeTotal: (graph.edges || []).filter(function (edge) {
                return ids[edge.a] && ids[edge.b];
            }).length,
            hiddenNodes: Math.max(0, nodes.length - shownNodes.length),
            hiddenEdges: Math.max(0, (graph.edges || []).filter(function (edge) {
                return ids[edge.a] && ids[edge.b];
            }).length - shownEdges.length)
        };
    }

    function graphLayout(nodes, type) {
        var width = 1180;
        var height = 800;
        var cx = width / 2;
        var cy = height / 2;
        var positions = {};
        var groups = {};
        for (var i = 0; i < nodes.length; i++) {
            var group = nodes[i].type;
            if (!groups[group]) groups[group] = [];
            groups[group].push(nodes[i]);
        }
        var order = type !== 'all' ? [type] : ['protocol', 'mac', 'host', 'service', 'domain', 'port'];
        var radii = { protocol: 88, mac: 170, host: 285, service: 360, domain: 435, port: 510 };
        for (var o = 0; o < order.length; o++) {
            var groupName = order[o];
            var list = groups[groupName] || [];
            if (!list.length) continue;
            list.sort(function (a, b) { return b.count - a.count || a.value.localeCompare(b.value); });
            var base = radii[groupName] || 280;
            var rings = list.length > 28 ? 2 : 1;
            var perRing = Math.ceil(list.length / rings);
            for (var r = 0; r < list.length; r++) {
                var ring = rings > 1 && r >= perRing ? 1 : 0;
                var ringList = rings === 1 ? list : list.slice(ring * perRing, (ring + 1) * perRing);
                var index = rings === 1 ? r : r - ring * perRing;
                var count = Math.max(1, ringList.length);
                var radius = type !== 'all' && count === 1 ? 0 : base + ring * 54;
                var angle = -Math.PI / 2 + (index / count) * Math.PI * 2 + (o * 0.17);
                positions[list[r].key] = {
                    x: cx + Math.cos(angle) * radius,
                    y: cy + Math.sin(angle) * radius,
                    angle: angle,
                    ring: ring
                };
            }
        }
        return { width: width, height: height, positions: positions };
    }

    function nodeRadius(node) {
        return Math.max(5, Math.min(17, 4.5 + Math.sqrt(node.count || 1) * 1.7));
    }

    function graphLabels(nodes, layout) {
        var labels = {};
        var boxes = [];
        var limit = nodes.length <= 28 ? nodes.length : 20;
        var byCount = nodes.slice().sort(function (a, b) { return b.count - a.count || a.value.localeCompare(b.value); });
        function hitsNode(box, ownKey) {
            for (var n = 0; n < nodes.length; n++) {
                if (nodes[n].key === ownKey) continue;
                var position = layout.positions[nodes[n].key];
                if (!position) continue;
                var radius = nodeRadius(nodes[n]) + 3;
                var closestX = Math.max(box.x, Math.min(position.x, box.x + box.w));
                var closestY = Math.max(box.y, Math.min(position.y, box.y + box.h));
                var dx = position.x - closestX;
                var dy = position.y - closestY;
                if (dx * dx + dy * dy < radius * radius) return true;
            }
            return false;
        }
        for (var i = 0; i < byCount.length && Object.keys(labels).length < limit; i++) {
            var node = byCount[i];
            var position = layout.positions[node.key];
            if (!position) continue;
            var text = clip(node.value, node.type === 'domain' ? 26 : 22);
            var width = Math.min(230, text.length * 6.0 + 8);
            var box = {
                x: position.x - width / 2,
                y: position.y + nodeRadius(node) + 3,
                w: width,
                h: 12
            };
            if (box.x < 2 || box.x + box.w > layout.width - 2 || box.y + box.h > layout.height - 2) continue;
            var collide = false;
            for (var b = 0; b < boxes.length; b++) {
                var other = boxes[b];
                if (box.x < other.x + other.w && box.x + box.w > other.x &&
                    box.y < other.y + other.h && box.y + box.h > other.y) {
                    collide = true;
                    break;
                }
            }
            if (collide || hitsNode(box, node.key)) continue;
            labels[node.key] = text;
            boxes.push(box);
        }
        return labels;
    }

    function graphSvg() {
        var host = panel();
        return host ? host.querySelector('.pcap-inv-graph-canvas .pcap-inv-svg') : null;
    }

    function graphBox(svg) {
        var box = svg && svg.viewBox && svg.viewBox.baseVal;
        return {
            width: box && box.width ? box.width : 1180,
            height: box && box.height ? box.height : 800
        };
    }

    function graphPoint(svg, clientX, clientY) {
        try {
            var point = svg.createSVGPoint();
            point.x = clientX;
            point.y = clientY;
            var matrix = svg.getScreenCTM();
            if (matrix) return point.matrixTransform(matrix.inverse());
        } catch (err) { }
        var rect = svg.getBoundingClientRect();
        return { x: clientX - rect.left, y: clientY - rect.top };
    }

    function syncGraphZoomUi() {
        if (!state.modal) return;
        var root = state.modal.root;
        var level = root.querySelector('[data-inv-zoom-level]');
        if (level) level.textContent = Math.round(state.graphZoom * 100) + '%';
        var atFit = state.graphZoom <= 1.001;
        var out = root.querySelector('[data-inv-zoom="out"]');
        var reset = root.querySelector('[data-inv-zoom="reset"]');
        if (out) out.disabled = atFit;
        if (reset) reset.disabled = atFit;
    }

    function applyGraphZoom() {
        var svg = graphSvg();
        if (!svg) return;
        var world = svg.querySelector('[data-inv-world]');
        if (!world) return;
        var box = graphBox(svg);
        var cx = box.width / 2;
        var cy = box.height / 2;
        world.setAttribute('transform', 'translate(' + state.graphPanX + ' ' + state.graphPanY + ') ' +
            'translate(' + cx + ' ' + cy + ') scale(' + state.graphZoom + ') ' +
            'translate(' + (-cx) + ' ' + (-cy) + ')');
        var labels = svg.querySelectorAll('.pcap-inv-node-label');
        var inverse = 1 / state.graphZoom;
        for (var i = 0; i < labels.length; i++) {
            if (state.graphZoom <= 1.001) {
                labels[i].removeAttribute('transform');
                continue;
            }
            var lx = parseFloat(labels[i].getAttribute('x'));
            var ly = parseFloat(labels[i].getAttribute('y'));
            if (!isFinite(lx) || !isFinite(ly)) continue;
            labels[i].setAttribute('transform', 'translate(' + lx + ' ' + ly + ') scale(' +
                inverse + ') translate(' + (-lx) + ' ' + (-ly) + ')');
        }
        svg.classList.toggle('pcap-inv-graph-zoomed', state.graphZoom > 1.001);
        syncGraphZoomUi();
    }

    function clampGraphPan() {
        var svg = graphSvg();
        if (!svg) return;
        var box = graphBox(svg);
        var maxX = Math.max(0, box.width * (state.graphZoom - 1) / 2);
        var maxY = Math.max(0, box.height * (state.graphZoom - 1) / 2);
        state.graphPanX = Math.max(-maxX, Math.min(maxX, state.graphPanX));
        state.graphPanY = Math.max(-maxY, Math.min(maxY, state.graphPanY));
    }

    function graphZoomAt(px, py, factor) {
        var svg = graphSvg();
        if (!svg) return;
        var box = graphBox(svg);
        var previous = state.graphZoom;
        var next = Math.max(1, Math.min(5, previous * factor));
        if (Math.abs(next - previous) < 0.0005) return;
        var cx = box.width / 2;
        var cy = box.height / 2;
        var ux = px == null ? cx : px;
        var uy = py == null ? cy : py;
        if (next <= 1.001) {
            state.graphPanX = 0;
            state.graphPanY = 0;
        } else {
            state.graphPanX = ux - cx - (ux - state.graphPanX - cx) * (next / previous);
            state.graphPanY = uy - cy - (uy - state.graphPanY - cy) * (next / previous);
        }
        state.graphZoom = next;
        clampGraphPan();
        applyGraphZoom();
    }

    function resetGraphZoom() {
        state.graphZoom = 1;
        state.graphPanX = 0;
        state.graphPanY = 0;
        state.graphDrag = null;
        applyGraphZoom();
    }

    function resetGraphZoomState() {
        state.graphZoom = 1;
        state.graphPanX = 0;
        state.graphPanY = 0;
        state.graphDrag = null;
    }

    function graphMarkup(brief) {
        var view = graphView(brief);
        var graph = brief.graph;
        if (!view.nodes.length) {
            return '<div class="pcap-inv-graph"><div class="pcap-inv-empty-small">No entity nodes are available for this view.</div></div>';
        }
        var layout = graphLayout(view.nodes, state.graphType);
        var colors = TYPE_COLOR;
        var svg = '<svg class="pcap-inv-svg" viewBox="0 0 ' + layout.width + ' ' + layout.height + '" role="img" aria-label="Entity co-occurrence graph">';
        svg += '<defs><radialGradient id="pcapInvGlow" cx="50%" cy="50%" r="50%">' +
            '<stop offset="0%" stop-color="#1a1a1c" stop-opacity="0.9"></stop>' +
            '<stop offset="100%" stop-color="#0d0d0f" stop-opacity="0"></stop>' +
            '</radialGradient></defs>';
        svg += '<rect x="0" y="0" width="' + layout.width + '" height="' + layout.height + '" fill="#0d0d0f"></rect>';
        svg += '<circle cx="' + (layout.width / 2) + '" cy="' + (layout.height / 2) + '" r="370" fill="url(#pcapInvGlow)"></circle>';
        svg += '<g class="pcap-inv-world" data-inv-world>';

        for (var e = 0; e < view.edges.length; e++) {
            var edge = view.edges[e];
            var a = layout.positions[edge.a];
            var b = layout.positions[edge.b];
            if (!a || !b) continue;
            var width = Math.max(0.7, Math.min(4, 0.7 + Math.log2((edge.count || 1) + 1) * 0.75));
            var kind = EDGE_COLOR[edge.type] || '#9aa0a8';
            svg += '<g class="pcap-inv-edge-group" data-inv-filter="' + attr(edge.filter) + '" role="button" tabindex="0" aria-label="' + attr(edge.label) + '">' +
                '<line class="pcap-inv-edge" x1="' + a.x.toFixed(1) + '" y1="' + a.y.toFixed(1) +
                    '" x2="' + b.x.toFixed(1) + '" y2="' + b.y.toFixed(1) +
                    '" stroke="' + kind + '" stroke-width="' + width.toFixed(2) + '" stroke-opacity="0.42"></line>' +
                '<line class="pcap-inv-edge-hit" x1="' + a.x.toFixed(1) + '" y1="' + a.y.toFixed(1) +
                    '" x2="' + b.x.toFixed(1) + '" y2="' + b.y.toFixed(1) + '" stroke="transparent" stroke-width="14"></line>' +
                '<title>' + esc(edge.label + ' · ' + plural(edge.count, 'packet') + ' · click to filter') + '</title>' +
            '</g>';
        }

        var labels = graphLabels(view.nodes, layout);
        for (var n = 0; n < view.nodes.length; n++) {
            var node = view.nodes[n];
            var position = layout.positions[node.key];
            if (!position) continue;
            var radius = nodeRadius(node);
            var color = colors[node.type] || '#717885';
            svg += '<g class="pcap-inv-node-group ' + node.type + '" style="color:' + color +
                '" data-inv-filter="' + attr(node.filter) +
                '" role="button" tabindex="0" aria-label="' + attr(node.label + ' ' + node.value) + '">' +
                '<circle class="pcap-inv-node-halo" cx="' + position.x.toFixed(1) + '" cy="' + position.y.toFixed(1) +
                    '" r="' + (radius + 5).toFixed(1) + '" fill="' + color + '" fill-opacity="0.12"></circle>' +
                '<circle class="pcap-inv-node" cx="' + position.x.toFixed(1) + '" cy="' + position.y.toFixed(1) +
                    '" r="' + radius.toFixed(1) + '" fill="' + color + '" fill-opacity="0.9" stroke="#0d0d0f" stroke-width="1.5"></circle>' +
                (labels[node.key] ? '<text class="pcap-inv-node-label" x="' + position.x.toFixed(1) +
                    '" y="' + (position.y + radius + 12).toFixed(1) + '" text-anchor="middle" fill="#eef0f3">' +
                    esc(labels[node.key]) + '</text>' : '') +
                '<title>' + esc(node.label + ': ' + node.value + ' · ' + plural(node.count, 'packet') + ' · click to filter') + '</title>' +
            '</g>';
        }
        svg += '</g></svg>';

        var typeOptions = '<option value="all">All entity types (' + graph.totalNodes + ')</option>';
        var order = ['host', 'domain', 'port', 'protocol', 'service', 'mac'];
        for (var ti = 0; ti < order.length; ti++) {
            var type = order[ti];
            if (!graph.typeCounts[type]) continue;
            typeOptions += '<option value="' + type + '"' + (state.graphType === type ? ' selected' : '') + '>' +
                TYPE_LABEL[type] + 's (' + graph.typeCounts[type] + ')</option>';
        }

        var legend = '<span class="pcap-inv-legend"><span class="pcap-inv-legend-dot host"></span>Host</span>' +
            '<span class="pcap-inv-legend"><span class="pcap-inv-legend-dot domain"></span>Domain</span>' +
            '<span class="pcap-inv-legend"><span class="pcap-inv-legend-dot port"></span>Port</span>' +
            '<span class="pcap-inv-legend"><span class="pcap-inv-legend-dot protocol"></span>Protocol</span>' +
            '<span class="pcap-inv-legend"><span class="pcap-inv-legend-dot service"></span>Service</span>' +
            '<span class="pcap-inv-legend"><span class="pcap-inv-legend-dot mac"></span>MAC</span>';

        var topNodes = view.nodes.slice(0, 18);
        var nodeList = '';
        for (var tn = 0; tn < topNodes.length; tn++) {
            nodeList += '<button type="button" class="pcap-inv-entity-row" data-inv-filter="' + attr(topNodes[tn].filter) + '">' +
                '<span class="pcap-inv-entity-dot" style="background:' + (colors[topNodes[tn].type] || '#717885') + '"></span>' +
                '<span class="pcap-inv-entity-name">' + esc(clip(topNodes[tn].value, 40)) + '</span>' +
                '<span class="pcap-inv-entity-count">' + topNodes[tn].count + '</span>' +
            '</button>';
        }

        var topEdges = view.edges.slice(0, 12);
        var edgeList = '';
        for (var te = 0; te < topEdges.length; te++) {
            edgeList += '<button type="button" class="pcap-inv-entity-row edge" data-inv-filter="' + attr(topEdges[te].filter) + '">' +
                '<span class="pcap-inv-entity-name">' + esc(clip(topEdges[te].label, 46)) + '</span>' +
                '<span class="pcap-inv-entity-count">' + topEdges[te].count + '</span>' +
            '</button>';
        }

        return '<div class="pcap-inv-graph">' +
            '<div class="pcap-inv-toolbar pcap-inv-graph-toolbar">' +
                '<div class="pcap-inv-legend-wrap">' + legend + '</div>' +
                '<label class="pcap-inv-select">Type <select data-inv-graph-type>' + typeOptions + '</select></label>' +
                '<span class="pcap-inv-hint">' + (view.hiddenNodes ?
                    'Showing ' + view.nodes.length + ' of ' + view.nodeTotal + ' entities by packet count.' :
                    'Showing all ' + plural(view.nodeTotal, 'entity', 'entities')) + '</span>' +
                (view.hiddenNodes || view.hiddenEdges ?
                    '<button type="button" class="pcap-btn" data-inv-graph-all>Show all</button>' :
                    (state.graphAll ? '<button type="button" class="pcap-btn" data-inv-graph-top>Show top</button>' : '')) +
                '<div class="pcap-inv-zoom" role="group" aria-label="Entity graph zoom">' +
                    '<button type="button" class="pcap-inv-zoom-btn" data-inv-zoom="out" title="Zoom out" aria-label="Zoom out">-</button>' +
                    '<span class="pcap-inv-zoom-level" data-inv-zoom-level aria-live="polite">100%</span>' +
                    '<button type="button" class="pcap-inv-zoom-btn" data-inv-zoom="in" title="Zoom in" aria-label="Zoom in">+</button>' +
                    '<button type="button" class="pcap-inv-zoom-btn pcap-inv-zoom-fit" data-inv-zoom="reset" title="Reset zoom">Fit</button>' +
                '</div>' +
            '</div>' +
            '<div class="pcap-inv-graph-layout">' +
                '<div class="pcap-inv-graph-canvas">' + svg + '</div>' +
                '<aside class="pcap-inv-graph-side">' +
                    '<div class="pcap-inv-graph-side-section"><h4>Entity filters</h4>' +
                        '<p>Click an entity to apply an exact display filter.</p>' +
                        '<div class="pcap-inv-entity-list">' + (nodeList || '<div class="pcap-inv-empty-small">No nodes.</div>') + '</div>' +
                    '</div>' +
                    '<div class="pcap-inv-graph-side-section"><h4>Top connections</h4>' +
                        '<p>Edges are packet co-occurrence, not a sample.</p>' +
                        '<div class="pcap-inv-entity-list">' + (edgeList || '<div class="pcap-inv-empty-small">No edges.</div>') + '</div>' +
                    '</div>' +
                '</aside>' +
            '</div>' +
            '<div class="pcap-inv-graph-note">' +
                '<strong>' + plural(view.nodeTotal, 'entity', 'entities') + '</strong> and <strong>' + plural(view.edgeTotal, 'connection') +
                '</strong> indexed from every packet in the capture. Scroll to zoom, drag to pan, and click a node or edge to filter the viewer. Labels are limited to the highest-volume entities so the view stays readable, and every displayed node remains clickable.' +
                (view.hiddenNodes ? ' Use Show all to render the remaining ' + view.hiddenNodes + ' entities.' : '') +
                (view.hiddenEdges ? ' ' + view.hiddenEdges + ' additional edges are hidden by the display limit.' : '') +
            '</div>' +
        '</div>';
    }

    // ------------------------------------------------------------------
    // Export
    // ------------------------------------------------------------------

    function ledgers(brief) {
        return brief.ledger || [];
    }

    function briefMarkdown(brief, narrative) {
        var lines = [];
        var stats = brief.stats;
        lines.push('# NETMAP Investigation Brief: ' + brief.capture);
        lines.push('');
        lines.push('- Generated: ' + brief.generatedAt);
        lines.push('- Packets: ' + stats.packets);
        lines.push('- Bytes: ' + stats.bytes);
        lines.push('- Duration: ' + fmtSeconds(stats.duration));
        lines.push('- Hosts: ' + stats.hosts);
        lines.push('- Domains: ' + stats.domains);
        lines.push('- Services: ' + stats.services);
        lines.push('- Active findings: ' + stats.active);
        lines.push('- Severity: ' + stats.severity.high + ' high, ' + stats.severity.medium + ' medium, ' +
            stats.severity.low + ' low, ' + stats.severity.info + ' info');
        lines.push('- Evidence integrity: ' + brief.integrity.cited + ' cited claims, ' +
            brief.integrity.uncited + ' uncited claims, ' + brief.integrity.missingFrames + ' missing frames');
        lines.push('');
        lines.push('## Assessment');
        lines.push('');
        for (var o = 0; o < brief.overview.length; o++) lines.push('- ' + brief.overview[o]);
        lines.push('');
        lines.push('## Ranked local hypotheses');
        lines.push('');
        for (var h = 0; h < brief.hypotheses.length; h++) {
            var hyp = brief.hypotheses[h];
            lines.push('### ' + hyp.rank + '. ' + hyp.title);
            lines.push('');
            lines.push('- Severity: ' + severityLabel(hyp.severity));
            lines.push('- Confidence: ' + hyp.confidence + '%');
            lines.push('- Evidence frames: ' + (hyp.frames.length ? hyp.frames.map(function (no) { return '#' + no; }).join(', ') : 'none'));
            if (hyp.filter) lines.push('- Display filter: `' + hyp.filter + '`');
            lines.push('');
            lines.push(hyp.statement);
            lines.push('');
        }
        lines.push('## Evidence ledger');
        lines.push('');
        if (!ledgers(brief).length) {
            lines.push('_No active local finding and no pinned finding for this capture. This is not proof that the traffic is benign._');
        }
        for (var l = 0; l < ledgers(brief).length; l++) {
            var item = ledgers(brief)[l];
            lines.push('### ' + (l + 1) + '. ' + item.title);
            lines.push('');
            lines.push('- Source: ' + (item.source === 'case' ? 'Pinned case finding' : 'Local deterministic detector'));
            lines.push('- Detector: ' + item.detectorLabel);
            lines.push('- Severity: ' + severityLabel(item.severity));
            lines.push('- Confidence: ' + item.confidence + '%');
            if (item.summary) lines.push('- Summary: ' + item.summary);
            if (item.detail) lines.push('- Detail: ' + item.detail);
            lines.push('- Evidence frames: ' + (item.frames.length ? item.frames.map(function (no) { return '#' + no; }).join(', ') : 'none'));
            if (item.missingFrames && item.missingFrames.length) {
                lines.push('- Missing frames: ' + item.missingFrames.map(function (no) { return '#' + no; }).join(', '));
            }
            if (item.filter) lines.push('- Display filter: `' + item.filter + '`');
            var entities = entityEntries(item.entities);
            if (entities.length) {
                lines.push('- Entities: ' + entities.map(function (entity) {
                    return TYPE_LABEL[entity.type] + ' ' + entity.value;
                }).join(', '));
            }
            if (item.nextPivot) lines.push('- Next pivot: ' + item.nextPivot);
            if (item.note) lines.push('- Analyst note: ' + item.note);
            lines.push('');
        }
        lines.push('## Timeline');
        lines.push('');
        if (!brief.timeline.length) {
            lines.push('_No timeline events._');
        }
        for (var t = 0; t < brief.timeline.length; t++) {
            var event = brief.timeline[t];
            var when = event.rel != null ? '+' + fmtSeconds(event.rel) : (event.at != null ? formatClock(event.at) : 'unknown time');
            lines.push('- ' + when + ' · frame #' + event.no + ' · ' + severityLabel(event.severity) + ' · ' +
                sourceLabel(event.source) + ': ' + event.title + (event.detail ? ' · ' + event.detail : ''));
        }
        lines.push('');
        lines.push('## Entity index');
        lines.push('');
        var graph = brief.graph || { nodes: [], edges: [] };
        for (var n = 0; n < graph.nodes.length && n < 60; n++) {
            lines.push('- ' + TYPE_LABEL[graph.nodes[n].type] + ' `' + graph.nodes[n].value + '` · ' +
                graph.nodes[n].count + ' packets');
        }
        if (!graph.nodes.length) lines.push('_No entities indexed._');
        lines.push('');
        lines.push('## Recommended next actions');
        lines.push('');
        for (var r = 0; r < brief.recommendations.length; r++) lines.push('- ' + brief.recommendations[r]);
        lines.push('');
        lines.push('## Case context');
        lines.push('');
        lines.push('- Case: ' + brief.case.name);
        lines.push('- Pinned findings: ' + brief.case.pinned);
        lines.push('- Packet references: ' + brief.case.refs);
        lines.push('');
        lines.push(brief.case.notes ? brief.case.notes : '_No case notes._');
        lines.push('');
        if (narrative) {
            lines.push('## AI narrative');
            lines.push('');
            lines.push('_AI explanation of the evidence ledger. It does not add findings. Citation check is reported below._');
            lines.push('');
            lines.push(sanitizeDashes(narrative.text));
            lines.push('');
            var check = citationCheck(narrative.text, brief);
            lines.push('- Citation check: ' + check.total + ' references, ' + check.connected +
                ' in the ledger, ' + check.outside + ' outside the ledger, ' + check.missing + ' not in this capture.');
            lines.push('');
            lines.push('- Model: ' + (narrative.model || 'configured provider'));
        }
        lines.push('');
        lines.push('_Generated by NETMAP. Local detection is deterministic. AI text is an explanation and is clearly separated from the evidence ledger._');
        return sanitizeDashes(lines.join('\n'));
    }

    function briefHtml(brief, narrative) {
        var title = 'NETMAP Investigation Brief: ' + brief.capture;
        var check = narrative ? citationCheck(narrative.text, brief) : null;
        var html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
            '<meta name="viewport" content="width=device-width, initial-scale=1">' +
            '<title>' + esc(title) + '</title>' +
            '<style>' +
            ':root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#050505;color:#a7adb8;' +
            'font:14.28px/1.65 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}' +
            'main{max-width:1120px;margin:0 auto;padding:44px 28px 70px}' +
            'header{border-bottom:1px solid #232327;padding-bottom:24px;margin-bottom:28px}' +
            '.kicker{color:#717885;font-size:11.22px;letter-spacing:2px;text-transform:uppercase;margin:0 0 8px}' +
            'h1{font-size:30.6px;line-height:1.2;margin:0 0 12px;color:#eef0f3}h2{font-size:19.38px;margin:34px 0 14px;color:#eef0f3;border-bottom:1px solid #232327;padding-bottom:8px}' +
            'h3{font-size:15.3px;margin:0 0 8px;color:#eef0f3}h4{font-size:13.26px;margin:0 0 6px;color:#eef0f3}' +
            'p{margin:8px 0}.muted{color:#717885}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:22px 0}' +
            '.stat{border:1px solid #232327;border-radius:6px;padding:12px;background:#0d0d0f}.stat b{display:block;font-size:19.38px;color:#eef0f3}' +
            '.card{border:1px solid #232327;border-radius:8px;padding:18px;margin:12px 0;background:#0d0d0f}' +
            '.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.pill{border:1px solid #232327;border-radius:999px;padding:2px 8px;font-size:11.22px;color:#717885}' +
            '.sev{font-size:10.2px;text-transform:uppercase;letter-spacing:1px;border-radius:999px;padding:2px 8px;border:1px solid #232327}' +
            '.high{color:#f87171;border-color:#7f1d1d}.medium{color:#fbbf24;border-color:#6b4d0f}.low{color:#a7adb8;border-color:#3a3a42}.info{color:#717885}' +
            '.frames{display:flex;gap:5px;flex-wrap:wrap;margin:10px 0}.frame{font-size:11.22px;color:#eef0f3;border:1px solid #3a3a42;border-radius:4px;padding:1px 6px}' +
            'code{background:#111111;border:1px solid #232327;border-radius:4px;padding:2px 6px;color:#eef0f3;word-break:break-word}' +
            '.code{display:block;padding:10px;margin:10px 0;white-space:pre-wrap}' +
            'table{width:100%;border-collapse:collapse;margin:12px 0;font-size:12.24px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #232327;padding:9px 8px}th{color:#717885;font-weight:400;text-transform:uppercase;font-size:10.2px;letter-spacing:1px}' +
            'ul,ol{padding-left:22px}li{margin:5px 0}.narrative{white-space:pre-wrap;background:#0d0d0f;border:1px solid #232327;border-radius:6px;padding:16px}' +
            '.warn{color:#fbbf24}.ok{color:#34d399}.note{color:#717885;font-size:12.24px}footer{margin-top:44px;padding-top:18px;border-top:1px solid #232327;color:#717885;font-size:11.22px}' +
            '@media print{body{background:#fff;color:#111}main{padding:0}.card,.stat,code,.narrative{background:#fff;border-color:#ddd}h1,h2,h3,h4{color:#111}.muted,.note,footer,.kicker{color:#555}}' +
            '</style></head><body><main>';

        html += '<header><p class="kicker">NETMAP investigation brief</p><h1>' + esc(brief.capture) + '</h1>' +
            '<p class="muted">Generated ' + esc(brief.generatedAt) + ' · Local deterministic detection · Evidence ledger first</p></header>';

        html += '<section class="stats">' +
            statHtml('Packets', brief.stats.packets) +
            statHtml('Data', fmtBytes(brief.stats.bytes)) +
            statHtml('Duration', fmtSeconds(brief.stats.duration)) +
            statHtml('Hosts', brief.stats.hosts) +
            statHtml('Domains', brief.stats.domains) +
            statHtml('Active findings', brief.stats.active) +
            statHtml('High severity', brief.stats.severity.high) +
            statHtml('Evidence integrity', brief.integrity.cited + ' cited / ' + brief.integrity.uncited + ' uncited') +
        '</section>';

        html += '<h2>Assessment</h2><div class="card"><ul>';
        for (var o = 0; o < brief.overview.length; o++) html += '<li>' + esc(brief.overview[o]) + '</li>';
        html += '</ul><p class="note">Claims: ' + brief.integrity.claims + ' · Cited: ' + brief.integrity.cited +
            ' · Uncited: ' + brief.integrity.uncited + ' · Missing frames: ' + brief.integrity.missingFrames + '</p></div>';

        html += '<h2>Ranked local hypotheses</h2>';
        for (var h = 0; h < brief.hypotheses.length; h++) {
            var hyp = brief.hypotheses[h];
            html += '<div class="card"><div class="row"><span class="pill">' + hyp.rank + '</span><h3>' + esc(hyp.title) + '</h3>' +
                '<span class="sev ' + esc(hyp.severity) + '">' + severityLabel(hyp.severity) + '</span>' +
                '<span class="pill">' + hyp.confidence + '% confidence</span></div>' +
                '<p>' + esc(hyp.statement) + '</p>' + frameHtml(hyp.frames) +
                (hyp.filter ? '<code class="code">' + esc(hyp.filter) + '</code>' : '') + '</div>';
        }

        html += '<h2>Evidence ledger</h2>';
        if (!ledgers(brief).length) {
            html += '<div class="card"><p>No active local finding and no pinned finding for this capture. This is not proof that the traffic is benign.</p></div>';
        }
        for (var l = 0; l < ledgers(brief).length; l++) {
            var item = ledgers(brief)[l];
            html += '<div class="card">' +
                '<div class="row"><h3>' + (l + 1) + '. ' + esc(item.title) + '</h3>' +
                    '<span class="sev ' + esc(item.severity) + '">' + severityLabel(item.severity) + '</span>' +
                    '<span class="pill">' + item.confidence + '%</span>' +
                    '<span class="pill">' + esc(item.source === 'case' ? 'Pinned' : 'Local') + '</span></div>' +
                '<p class="muted">' + esc(item.detectorLabel) + ' · ' + esc(item.summary || '') + '</p>' +
                frameHtml(item.frames) +
                (item.detail ? '<p>' + esc(item.detail) + '</p>' : '') +
                (item.filter ? '<code class="code">' + esc(item.filter) + '</code>' : '') +
                (item.nextPivot ? '<p><b>Next pivot:</b> ' + esc(item.nextPivot) + '</p>' : '') +
                (item.note ? '<p><b>Analyst note:</b> ' + esc(item.note) + '</p>' : '') +
            '</div>';
        }

        html += '<h2>Timeline</h2><div class="card"><table><thead><tr><th>Time</th><th>Frame</th><th>Source</th><th>Event</th></tr></thead><tbody>';
        if (!brief.timeline.length) {
            html += '<tr><td colspan="4" class="muted">No timeline events.</td></tr>';
        }
        for (var t = 0; t < brief.timeline.length; t++) {
            var event = brief.timeline[t];
            var when = event.rel != null ? '+' + fmtSeconds(event.rel) : (event.at != null ? formatClock(event.at) : 'unknown');
            html += '<tr><td>' + esc(when) + '</td><td>#' + Number(event.no) + '</td><td>' +
                esc(sourceLabel(event.source)) + '</td><td><b>' + esc(event.title) + '</b>' +
                (event.detail ? '<br><span class="muted">' + esc(event.detail) + '</span>' : '') + '</td></tr>';
        }
        html += '</tbody></table></div>';

        html += '<h2>Recommended next actions</h2><div class="card"><ol>';
        for (var r = 0; r < brief.recommendations.length; r++) html += '<li>' + esc(brief.recommendations[r]) + '</li>';
        html += '</ol></div>';

        html += '<h2>Case context</h2><div class="card"><p><b>' + esc(brief.case.name) + '</b></p>' +
            '<p class="muted">' + brief.case.pinned + ' pinned findings · ' + brief.case.refs + ' packet references</p>' +
            '<p>' + (brief.case.notes ? esc(brief.case.notes) : 'No case notes.') + '</p></div>';

        if (narrative) {
            html += '<h2>AI narrative</h2><div class="card"><p class="muted">AI explanation of the evidence ledger. It does not add findings.</p>' +
                '<div class="narrative">' + esc(sanitizeDashes(narrative.text)) + '</div>' +
                '<p class="' + (check && (check.bad || check.outside) ? 'warn' : 'ok') + '">Citation check: ' +
                (check ? check.total + ' references, ' + check.connected + ' in the ledger, ' +
                    check.outside + ' outside the ledger, ' + check.missing + ' not in this capture' : 'not available') + '.</p>' +
                '<p class="note">Model: ' + esc(narrative.model || 'configured provider') + '</p></div>';
        }

        html += '<footer>Generated by NETMAP. Local detection is deterministic. AI text is an explanation and is clearly separated from the evidence ledger.</footer>';
        html += '</main></body></html>';
        return sanitizeDashes(html);
    }

    function statHtml(label, value) {
        return '<div class="stat"><b>' + esc(value) + '</b>' + esc(label) + '</div>';
    }

    function frameHtml(frames) {
        if (!frames || !frames.length) return '<p class="warn">No frame reference attached.</p>';
        var html = '<div class="frames">';
        for (var i = 0; i < frames.length && i < 60; i++) {
            html += '<span class="frame">#' + Number(frames[i]) + '</span>';
        }
        if (frames.length > 60) html += '<span class="pill">+' + (frames.length - 60) + ' more</span>';
        html += '</div>';
        return html;
    }

    function exportBrief(kind) {
        if (!state.brief) {
            toast('Generate the brief first.');
            return;
        }
        var stem = fileStem(state.brief.capture);
        var stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, '').replace('T', '-');
        if (kind === 'html') {
            download(stem + '-investigation-' + stamp + '.html', briefHtml(state.brief, state.narrative), 'text/html');
            toast('Investigation HTML exported.');
        } else {
            download(stem + '-investigation-' + stamp + '.md', briefMarkdown(state.brief, state.narrative), 'text/markdown');
            toast('Investigation Markdown exported.');
        }
    }

    // ------------------------------------------------------------------
    // Natural language filter assistant
    // ------------------------------------------------------------------

    function openFilterAssistant() {
        var viewerApi = api();
        if (!viewerApi) return false;
        var viewer = viewerApi.active();
        if (!viewer || !viewer.packets || !viewer.packets.length) {
            toast('Load a capture before using the filter assistant.');
            return false;
        }
        if (!window.PcapAI || typeof window.PcapAI.suggestFilter !== 'function') {
            toast('The AI filter assistant is unavailable.');
            return false;
        }

        var dialog = viewerApi.openDialog('AI Filter Assistant', filterShell(viewer), {
            className: 'pcap-inv-filter-modal'
        });
        if (!dialog) return false;

        var promptEl = dialog.body.querySelector('[data-fa-prompt]');
        var filterEl = dialog.body.querySelector('[data-fa-filter]');
        var statusEl = dialog.body.querySelector('[data-fa-status]');
        var resultEl = dialog.body.querySelector('[data-fa-result]');
        var validateEl = dialog.body.querySelector('[data-fa-validate]');
        var previewEl = dialog.body.querySelector('[data-fa-preview]');
        var rationaleEl = dialog.body.querySelector('[data-fa-rationale]');
        var explainEl = dialog.body.querySelector('[data-fa-explain]');
        var explainBody = dialog.body.querySelector('[data-fa-explain-body]');
        var suggestBtn = dialog.body.querySelector('[data-fa-suggest]');
        var applyBtn = dialog.body.querySelector('[data-fa-apply]');
        var copyBtn = dialog.body.querySelector('[data-fa-copy]');
        var explainBtn = dialog.body.querySelector('[data-fa-explain-btn]');
        var timer = null;
        var last = null;

        function setStatus(html, kind) {
            statusEl.className = 'pcap-inv-fa-status ' + (kind || '');
            statusEl.innerHTML = html;
        }

        function validate(immediate) {
            clearTimeout(timer);
            if (!immediate) {
                timer = setTimeout(function () { validate(true); }, 140);
                return;
            }
            var expr = filterEl.value.trim();
            explainEl.hidden = true;
            if (!expr) {
                last = null;
                validateEl.innerHTML = '<span class="pcap-inv-hint">Enter a filter to preview matches.</span>';
                previewEl.innerHTML = '';
                return;
            }
            var result = viewerApi.queryPackets(expr, 8);
            last = result;
            if (result.error) {
                filterEl.classList.add('invalid');
                validateEl.innerHTML = '<span class="pcap-inv-fa-error"><strong>Filter error.</strong> ' + esc(result.error) + '</span>';
                previewEl.innerHTML = '';
                return;
            }
            filterEl.classList.remove('invalid');
            validateEl.innerHTML = '<span class="pcap-inv-fa-ok"><strong>' + plural(result.total, 'packet') +
                ' match.</strong> Validated locally. Nothing is applied until you approve.</span>';
            if (!result.total) {
                previewEl.innerHTML = '<div class="pcap-inv-fa-empty">This filter matches no packets. Check the value or broaden the expression.</div>';
                return;
            }
            var rows = '';
            for (var i = 0; i < result.indices.length; i++) {
                var index = result.indices[i];
                var packet = viewer.packets[index];
                if (!packet) continue;
                var src = packet.dec && packet.dec.src ? packet.dec.src : '';
                var dst = packet.dec && packet.dec.dst ? packet.dec.dst : '';
                var proto = packet.dec && packet.dec.proto ? packet.dec.proto : '';
                rows += '<button type="button" class="pcap-inv-fa-frame" data-fa-frame="' + Number(packet.no) + '">' +
                    '<span class="pcap-inv-fa-frame-no">#' + Number(packet.no) + '</span>' +
                    '<span class="pcap-inv-fa-frame-proto">' + esc(proto) + '</span>' +
                    '<span class="pcap-inv-fa-frame-addr">' + esc(clip(src + ' -> ' + dst, 48)) + '</span>' +
                    '<span class="pcap-inv-fa-frame-info">' + esc(clip(packet.dec && packet.dec.info ? packet.dec.info : '', 72)) + '</span>' +
                '</button>';
            }
            previewEl.innerHTML = '<div class="pcap-inv-fa-preview-head">First ' + result.indices.length + ' matching frames</div>' + rows;
        }

        dialog.body.addEventListener('click', function (event) {
            var example = event.target.closest('[data-fa-example]');
            if (example) {
                promptEl.value = example.getAttribute('data-fa-example');
                promptEl.focus();
                return;
            }
            var frame = event.target.closest('[data-fa-frame]');
            if (frame) {
                var no = parseInt(frame.getAttribute('data-fa-frame'), 10);
                if (viewerApi.selectNo(no)) {
                    dialog.close();
                    toast('Selected frame #' + no + '.');
                }
                return;
            }
            if (event.target.closest('[data-fa-settings]')) {
                openAISettings();
                return;
            }
            if (event.target.closest('[data-fa-suggest]')) {
                var prompt = promptEl.value.trim();
                if (!prompt) {
                    setStatus('<span class="pcap-inv-fa-error">Describe the traffic you want to see first.</span>', 'error');
                    promptEl.focus();
                    return;
                }
                if (window.PcapAI.isConfigured && !window.PcapAI.isConfigured()) {
                    setStatus('<span class="pcap-inv-fa-error">No model provider is configured. The assistant needs a provider, but all validation stays local.</span> ' +
                        '<button type="button" class="pcap-btn" data-fa-settings>Open AI settings</button>', 'error');
                    return;
                }
                suggestBtn.disabled = true;
                suggestBtn.textContent = 'Thinking…';
                setStatus('<span class="pcap-inv-fa-loading"><span class="pcap-inv-spinner small" aria-hidden="true"></span> Asking the model for one filter. The capture itself is not uploaded, only the summary shown in AI settings context.</span>', '');
                window.PcapAI.suggestFilter(prompt, { viewer: viewer }).then(function (result) {
                    filterEl.value = result.filter || '';
                    rationaleEl.innerHTML = result.rationale ? '<span>Why this filter</span><p>' + esc(sanitizeDashes(result.rationale)) + '</p>' : '';
                    if (result.terms && result.terms.length) {
                        rationaleEl.innerHTML += '<div class="pcap-inv-fa-terms">' + result.terms.map(function (term) {
                            return '<span>' + esc(sanitizeDashes(term)) + '</span>';
                        }).join('') + '</div>';
                    }
                    setStatus('<span class="pcap-inv-fa-ok"><strong>Filter proposed.</strong> Review it, validate the match count, then apply it.</span>', 'ok');
                    resultEl.hidden = false;
                    validate(true);
                }).catch(function (err) {
                    setStatus('<span class="pcap-inv-fa-error">' + esc(err && err.message ? err.message : String(err)) + '</span>', 'error');
                }).then(function () {
                    suggestBtn.disabled = false;
                    suggestBtn.textContent = 'Suggest filter';
                });
                return;
            }
            if (event.target.closest('[data-fa-copy]')) {
                copyText(filterEl.value.trim());
                return;
            }
            if (event.target.closest('[data-fa-explain-btn]')) {
                explainEl.hidden = false;
                var info = viewerApi.explainFilter(filterEl.value.trim());
                if (info.error) {
                    explainBody.innerHTML = '<span class="pcap-inv-fa-error">' + esc(info.error) + '</span>';
                } else {
                    explainBody.innerHTML = '<p>' + esc(info.text) + '</p>' +
                        (info.terms.length ? '<div class="pcap-inv-fa-terms">' + info.terms.map(function (term) {
                            return '<span>' + esc(term) + '</span>';
                        }).join('') + '</div>' : '');
                }
                return;
            }
            if (event.target.closest('[data-fa-apply]')) {
                var expr = filterEl.value.trim();
                if (!expr) {
                    setStatus('<span class="pcap-inv-fa-error">There is no filter to apply.</span>', 'error');
                    return;
                }
                var current = viewerApi.queryPackets(expr, 1);
                if (current.error) {
                    setStatus('<span class="pcap-inv-fa-error"><strong>Filter error.</strong> ' + esc(current.error) + '</span>', 'error');
                    return;
                }
                if (!viewerApi.setFilter(expr)) {
                    setStatus('<span class="pcap-inv-fa-error">The filter could not be applied.</span>', 'error');
                    return;
                }
                if (current.nos.length) viewerApi.selectNo(current.nos[0]);
                dialog.close();
                toast('Filter applied: ' + plural(current.total, 'packet') + ' match.');
                return;
            }
        });

        filterEl.addEventListener('input', function () { validate(false); });
        promptEl.addEventListener('keydown', function (event) {
            if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                event.preventDefault();
                suggestBtn.click();
            }
        });
        dialog.onClose(function () {
            clearTimeout(timer);
        });
        setTimeout(function () { promptEl.focus(); }, 30);
        return true;
    }

    function filterShell(viewer) {
        var examples = [
            'DNS NXDOMAIN responses',
            'TLS handshakes to external hosts',
            'HTTP POST requests',
            'TCP resets and refused connections',
            'Traffic from a specific host',
            'Large packets over 1200 bytes'
        ];
        var exampleHtml = '';
        for (var i = 0; i < examples.length; i++) {
            exampleHtml += '<button type="button" class="pcap-inv-fa-example" data-fa-example="' + attr(examples[i]) + '">' + esc(examples[i]) + '</button>';
        }
        return '<div class="pcap-inv-fa">' +
            '<div class="pcap-inv-fa-intro">' +
                '<p>Describe the packets you want in plain language. The model proposes one display filter, then NETMAP validates it against <strong>' +
                    esc(viewer.name || 'the capture') + '</strong> and previews the exact matches before anything changes.</p>' +
                '<p class="pcap-inv-hint">Local validation · local preview · explicit approval</p>' +
            '</div>' +
            '<label class="pcap-inv-fa-field">What do you want to see?' +
                '<textarea data-fa-prompt rows="3" placeholder="For example: DNS NXDOMAIN responses from 10.0.0.8 in the first two minutes"></textarea>' +
            '</label>' +
            '<div class="pcap-inv-fa-examples">' + exampleHtml + '</div>' +
            '<div class="pcap-inv-fa-actions">' +
                '<button type="button" class="pcap-btn primary" data-fa-suggest>✦ Suggest filter</button>' +
                '<span class="pcap-inv-hint"><kbd>Ctrl</kbd> + <kbd>Enter</kbd> to suggest</span>' +
            '</div>' +
            '<div class="pcap-inv-fa-status" data-fa-status role="status"><span class="pcap-inv-hint">Waiting for a request.</span></div>' +
            '<div class="pcap-inv-fa-result" data-fa-result hidden>' +
                '<label class="pcap-inv-fa-field">Proposed filter' +
                    '<textarea data-fa-filter rows="2" spellcheck="false" placeholder="dns && dns.flags.rcode == 3"></textarea>' +
                '</label>' +
                '<div class="pcap-inv-fa-result-actions">' +
                    '<button type="button" class="pcap-btn primary" data-fa-apply>Apply filter</button>' +
                    '<button type="button" class="pcap-btn" data-fa-copy>Copy</button>' +
                    '<button type="button" class="pcap-btn" data-fa-explain-btn>Explain</button>' +
                '</div>' +
                '<div class="pcap-inv-fa-validate" data-fa-validate></div>' +
                '<div class="pcap-inv-fa-preview" data-fa-preview></div>' +
                '<div class="pcap-inv-fa-rationale" data-fa-rationale></div>' +
                '<div class="pcap-inv-fa-explain" data-fa-explain hidden><h4>Filter explanation</h4><div data-fa-explain-body></div></div>' +
            '</div>' +
        '</div>';
    }

    window.PcapInvestigate = {
        open: open,
        openFilterAssistant: openFilterAssistant,
        briefMarkdown: briefMarkdown,
        briefHtml: briefHtml,
        citationCheck: function (text, brief) { return citationCheck(text, brief); },
        sanitizeDashes: sanitizeDashes
    };
})();
