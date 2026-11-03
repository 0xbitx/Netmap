# NETMAP

NETMAP is a standalone, browser-based packet analyzer with a Wireshark-style workflow.
It gives you a complete investigation surface in one tab: open a `pcap` or `pcapng`
capture, filter it with Wireshark display-filter syntax, inspect every protocol layer,
follow TCP and UDP streams, and move from raw frames to evidence-linked findings without
a backend, agent, or build step.

The analyzer reads classic pcap and pcapng in both byte orders, parses captures up to
128 MB in full, and keeps the interface responsive with chunked decoding and a
virtualized packet list. A near-fullscreen traffic map turns every group, connection and
packet into a navigable graph. Local triage then checks for beaconing, scans, DNS
anomalies, credential exposure, ARP conflicts, lateral movement, rare protocols and
long-lived flows. Each finding carries severity, confidence, frame references, a display
filter and a next pivot. Build a browser-local case with notes and packet references,
export it as Markdown or JSON, and compare a baseline capture to surface novel hosts,
domains, service endpoints and MAC addresses.

A built-in AI analyst works alongside the deterministic tools. Ask about the loaded
capture, the current filter or the selected frame; open a packet dossier; let the model
request bounded, read-only packet data; and review suggested filters, packet jumps,
panels and map moves before anything changes. Captures stay local unless you use the AI
analyst, which sends context only to the provider you configure. Preferences and case
data are stored in the browser.

## Features

- **Capture formats**: classic pcap and pcapng, both byte orders, including
  nanosecond timestamps and multiple pcapng interfaces.
- **Link layers**: Ethernet, Linux cooked capture (SLL), raw IPv4 and raw IPv6.
- **Dissectors**: Ethernet, VLAN/QinQ, IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6,
  DNS, HTTP, TLS, SSH and NTP.
- **Massive captures**: no packet-count cap. Captures up to 128 MB are parsed in
  full, decoded in chunks with progress, and displayed through a virtualized packet
  list that only renders the visible window (plus a small overscan).
- **Display filters**: Wireshark syntax with boolean logic, parentheses, CIDR,
  quoted strings, `contains`, `matches`, hex values, and a built-in help panel
  (`F1`).
- **Packet details**: collapsible protocol tree, field values, hex dump, and raw
  bytes.
- **Analysis tools**: a near-fullscreen radial traffic graph with an all-connections view, a
  packet-level graph, grouped protocol nodes, packet halos in capture order, an integrated
  packet story and a resizable details pane, plus follow
  TCP/UDP streams, protocol hierarchy, conversations, endpoints, expert information, HTTP
  objects, IO graph, and coloring rules.
- **Local triage**: deterministic, evidence-linked detectors for beaconing, scans and
  fan-out, DNS tunneling/TXT/NXDOMAIN anomalies, outbound asymmetry, cleartext credentials,
  ARP conflicts, lateral movement, rare protocols and long-lived flows. Every finding
  carries severity, confidence, an explanation, exact frame references, a display filter,
  entities and a next pivot, and actions to ask the AI, show it on the map, follow the
  stream, pin it to a case or mark it benign.
- **Case file**: pin findings into one browser-local case with notes and packet
  references, then export the case as Markdown or JSON. Credential values are redacted.
- **Investigation workspace**: click **Investigate** to build an evidence-led brief from
  the deterministic detectors, the case file and every decoded packet. The brief ranks
  local hypotheses, attaches exact frame citations to every claim, lists next pivots and
  exports Markdown or standalone HTML. A timeline folds in active findings and pinned
  case items, and an entity graph indexes every host, domain, port, protocol and service.
  Clicking a node or edge applies an exact display filter. An AI narrative
  explains the ledger, is labelled as explanation only and is checked for frame
  citations before export.
- **AI filter assistant**: click **✦** beside the display filter help button, describe
  the traffic in plain language and review the proposed filter. NETMAP validates the
  expression locally, shows the live match count and previews exact frames before the
  filter is applied. The filter remains editable, copyable and explainable in plain
  language.
- **Capture correlation**: load a baseline capture locally and flag novel hosts, domains,
  service endpoints and MAC addresses with their first-seen frames and a frame-number
  filter. The active viewer is never replaced.
- **Workflow**: find packet, go to packet, marks, comments, custom columns, time
  display formats, sorting, zoom, and keyboard shortcuts.
- **AI analyst**: ask questions about the loaded capture, current filter,
  selected packet, conversations, endpoints and protocol mix. The same analyst can be
  opened inside the traffic map to explain the live graph, trace a selection and propose
  map moves. Open a local packet dossier for any frame, request a deep field-level AI
  analysis, and follow clickable `#12` frame citations. The model can request read-only
  packet data through bounded tools. The panel can propose filters, packet jumps, marks,
  analysis panels and map actions; actions apply only when you approve them (or if you
  explicitly enable auto-apply). A dedicated AI filter assistant converts natural
  language into locally validated filters, and the investigation workspace uses the AI
  to narrate the local evidence ledger with frame citations.
- **Privacy**: files are read with the browser `File` API and parsed locally. The AI
  analyst sends context only to the provider you configure. Preferences and AI settings
  are stored in `localStorage`.

## Traffic map

Click **Map** in the toolbar (or choose **Statistics ▸ Traffic Map**) to open a
near-fullscreen map of the loaded capture. The viewer stays open behind it, and the map
opens with the browser Fullscreen button available in the viewer header.

The map does not cap, sample, or aggregate connections. Every group, connection, and
packet is represented:

- **Graph** is the primary radial view. Every group or connection in the current scope
  is drawn as its own node around the center, with node area following bytes or packet
  count. Each connection node carries a halo with one dot per packet, ordered clockwise
  from the connection's first packet; forward packets are bright, reverse packets are
  muted, a dashed inner track and arrow show capture order, and the first and last
  packets are ringed. Labels show endpoint A `↔` endpoint B, protocol, packet and byte
  totals, duration and frame range; endpoint ports are dropped on narrow panes and stay
  available in the node tooltip. Group labels show the same totals for every
  connection beneath them. Labels are collision-packed: a label that cannot fit is
  suppressed rather than overlapped, and hover or selection reveals it. Use **All
  connections / Groups** to switch between one node per connection and one node per
  protocol group. Hover a node for its frame-level summary, click to inspect it, and
  double-click to focus its packets.
- **Zoom and pan**: use the **- / + / Fit** controls in the map footer, scroll over the
  graph, or drag a zoomed map. The footer never covers nodes, halos, labels or packet
  dots.
- **Packet map**: double-click a connection (in Graph or Tiles) to open its packet
  graph. Every frame in that conversation becomes its own node in capture order, colored
  by direction. Labels carry `#frame · protocol · bytes`, the source `→` destination
  route and the packet summary; first and last frames are ringed, and labels that would
  collide are tucked away until hover or selection. Click a node to select that exact
  packet in the viewer; the packet story, breadcrumb and details panel all follow it.
  Double-click the center dot to go back to the connection's group.
- **Tiles** is the compact treemap view. Tile area is proportional to bytes or packet
  count, and every tile is clickable.
- **Packet story** lives inside the graph as a drawer below it. It lists every packet in
  the current scope, in chronological order or grouped by connection, with frame number,
  relative time, protocol, endpoints, info, byte count, and layer chain. Click any row to
  select that packet in the packet list and highlight its dot in the map. Collapse the
  drawer with its tab or open it full-screen with **Full screen**.
- **Right-click packet actions**: right-click a halo dot, packet node, story row, or
  packet row in the details pane to open a context menu. Choose **Select Packet #N** to
  select and highlight it, **Open in Packet List**, **Ask AI About Packet #N** to open the
  map analyst with a grounded prompt (the packet is selected first), mark/unmark, follow
  a TCP/UDP stream, or copy the summary and addresses. Right-click a connection or group
  node for selection, AI, packet-story, stream and filter actions. Right-click empty
  graph space for **Explain This View**, **Back to Top** and **Reset Zoom**.
- The scope follows your selection: click a protocol group or connection node (or its
  halo dot) and the story below updates to every packet in that group or connection.
  Use **Back to top** or the breadcrumb to return to the whole capture.
- The right detail pane is resizable: drag the separator beside it, focus it and use
  ←/→ (Shift for larger steps) or Home/End, or double-click it to reset. The width is
  remembered for the next visit. The pane lists every group/connection and every packet
  in the selected scope (large captures load further packets on demand). From there you
  can open the story, select a packet, filter the group or connection, follow a
  TCP/UDP stream, or ask the map analyst about that selection.

The map itself reads only the capture already loaded in the tab. It does not contact the
network on open; only the map analyst sends anything, and only after you ask a
question.

### Map analyst

Click **✦ AI** in the map toolbar or press `Ctrl+I` while the map is open. The chat docks
where the details rail sits and replaces it while open, so the graph keeps the remaining
space. `Esc` closes the chat before the map, and `Ctrl+I` toggles it from anywhere in the
map.

The chat is resizable: drag the separator on its left, focus it and use ←/→ (Shift for
larger steps) or Home/End, or double-click it to reset. The width is remembered for the
next visit. On narrow screens it becomes an overlay above the graph instead.

The map analyst reuses the provider configured for the main AI panel. The gear button in
the chat header opens the same settings dialog above the map. Each question includes the
normal capture context plus a live `[TRAFFIC MAP CONTEXT]` snapshot:

- the current layout, grouping, area metric, zoom, story drawer and breadcrumb;
- the current scope and selection with their exact node refs;
- every group and up to 160 connections, with endpoints, protocol, packet/byte totals,
  duration, frame range and display filter;
- the ordered packet sequence for a selected connection (up to 90 frames per
  conversation), plus packet detail for the current scope and selection.

The model can request read-only packet tools (`packet`, `packets`, `stream`, `range`,
`expert`) exactly like the main analyst, and can propose map moves in a fenced
`pcap-map-action` block: select or drill a node, go back or to the top, change grouping,
layout, level or area metric, zoom/fit, select a packet, change story order, open or
collapse the story, or open the full packet story. Suggestions appear as approval cards.
They are never applied unless you press **Apply** / **Apply all**, or enable
**Auto-apply suggested UI actions** in AI settings. A wrong or stale node ref fails
visibly with the reason and leaves the map unchanged.

### Local triage, case file and capture comparison

Click **◆ Triage** in the map toolbar to replace the details rail with the local triage
rail. Detection is deterministic and runs entirely in the browser: it never contacts a
provider and never samples or aggregates the capture. Triage and the map chat share one
auxiliary slot: opening either one closes the other. The detectors cover:

- periodic beaconing over TCP or UDP, including DNS query cadence;
- fan-out to many hosts and port scans against one host;
- long, high-entropy DNS labels (tunneling), TXT activity and NXDOMAIN bursts;
- outbound/inbound byte asymmetry consistent with exfiltration;
- cleartext HTTP Basic/form and FTP/Telnet credentials (values are redacted);
- ARP conflicts and one MAC claiming many addresses;
- lateral movement across remote-access services;
- rare protocols and long-lived flows.

Every finding includes severity, confidence, a plain-language explanation, exact frame
references, a copyable display filter, the entities involved and a suggested next pivot.
Each card offers **Ask AI**, **Show on map**, **Follow stream**, **Pin to case** and
**Mark benign**; the filter can also be applied directly. **Ask AI** closes triage, opens
the map chat and sends the finding's local evidence as a bounded prompt. Triage findings
are also added to the live `[TRAFFIC MAP CONTEXT]`, so follow-up questions can correlate
them with the graph. The model is instructed to explain the existing evidence, not invent
new detections. Benign marks are stored by finding fingerprint in `localStorage` and can
be revealed again with **Show benign**.

The **Case** tab stores one browser-local case: a name, free-form notes, pinned findings
and packet references. Pinning a finding automatically adds its evidence frames as packet
references; the selected map packet can also be added manually. **Export Markdown** and
**Export JSON** download the complete case, including notes, findings, evidence frames,
filters, entities and packet references. Credential values are deliberately excluded.

The **Compare** tab loads a second baseline capture without replacing the active viewer.
Choose a `.pcap`/`.pcapng` file under the same 128 MB guard; it is parsed and decoded
locally in the same chunked pipeline. Comparison findings group novel **domains**,
**hosts**, **service endpoints** and **MAC addresses** that do not appear in the baseline,
with each entity's first-seen frame and a `frame.number == …` filter. Use **Show in
Findings** to review or pin them. A set difference is a lead, not a verdict: confirm the
first-seen frames and the surrounding stream before drawing conclusions. The case and
benign marks survive page reloads; the loaded baseline itself is session-only.

### Triage sample captures

The bundled demo capture exercises every deterministic detector:

- `samples/sample.pcap`: 329 packets / 680 s covering TCP, UDP and DNS beaconing;
  fan-out and port-scan shapes; DNS tunneling, TXT and NXDOMAIN activity; outbound
  asymmetry; HTTP Basic, HTTP form, FTP and Telnet credentials; an ARP conflict and one
  MAC claiming many addresses; lateral movement; GRE; and a long-lived flow.
- `samples/triage-baseline.pcap`: 10 packets of normal traffic for the **Compare** tab.

Open `sample.pcap`, click **◆ Triage**, and expect **18 active findings** across all
nine detector families. The same capture feeds the bundled **Investigate** demo. To
compare, open **Compare**, load `triage-baseline.pcap`, and use **Show in Findings** to
inspect the novel domains, hosts, service endpoints and MAC address. Credential values
in the sample are fake.

## Investigation workspace

Click **Investigate** in the toolbar, or choose **Analyze ▸ Investigation Brief**, to
open a near-fullscreen workspace built entirely from the loaded capture and the local
case file. It uses the same near-fullscreen layout as the traffic map. The toolbar also
offers **Markdown**, **HTML**, **Copy brief** and **Rescan**.

The workspace has three views:

- **Brief** starts with a local assessment and ranked hypotheses. Every hypothesis,
  detector finding and pinned case finding is listed in an evidence ledger with severity,
  confidence, exact frame references, a display filter, entities, the next pivot and a
  citation state. A claim with no frame reference is marked uncited. Missing case frames
  are reported rather than hidden.
- **Timeline** keeps every active finding and every pinned finding or packet reference
  for the current capture. Events are sorted by capture time, can be filtered by severity
  or case origin, and select the exact frame when clicked. Nothing is sampled.
- **Entity graph** indexes hosts, domains, ports, protocols, services and MAC addresses
  from every packet. Nodes are color coded by entity type: hosts blue, domains violet,
  ports amber, protocols teal, services green and MAC addresses rose. Edges represent
  packet co-occurrence and follow the relationship type. Scroll to zoom toward the
  cursor, drag to pan while zoomed, or use the `-`, `+` and `Fit` controls in the graph
  toolbar. Labels stay readable while zoomed. Click any node or edge to apply an exact
  display filter. Labels are limited to the highest-volume entities so the graph stays
  readable, but every node remains clickable and the counters use all packets.

The **AI narrative** section receives the local brief, not the raw capture. It is
instructed to explain only the evidence ledger and to cite frames in `#123` form. The
workspace checks those citations against the ledger and the current capture, and reports
references that fall outside the evidence. The narrative is marked as AI explanation in
both Markdown and HTML exports and never replaces or extends the local findings.

The exported Markdown and standalone HTML reports include the assessment, hypotheses,
complete evidence ledger, full timeline, entity index, recommendations, case notes and
the AI narrative with its citation check.

### AI filter assistant

Click **✦** beside the display filter help button, or choose
**Analyze ▸ AI Filter Assistant**. Describe the packets you want in plain language and
press **✦ Suggest filter** (or `Ctrl` + `Enter`). The assistant asks the configured model
for one display filter using the capture summary and the supported filter grammar.

The proposal is never applied automatically. NETMAP first validates the expression with
the local filter parser, shows whether it is valid, reports the exact match count and
previews the first matching frames. You can edit the filter, copy it, apply it, or press
**Explain** for a local plain-language explanation of the expression. Applying the filter
selects the first match and closes the assistant. Invalid expressions stay local and are
rejected before the viewer changes.

## AI analyst

The AI panel is built into the analyzer and opens with the **AI** toolbar button or
`Ctrl+I`. The traffic map opens its own analyst from the map toolbar (also `Ctrl+I`);
both surfaces share the same provider settings and chat transport. It uses an
OpenAI-compatible chat endpoint; no provider or key is bundled with this project.

1. Open a capture, then click the gear icon in the AI panel.
2. Choose a preset: OpenRouter (default), DeepSeek direct, Ollama, LM Studio, or
   custom. Enter the base URL, model and API key.
3. Save and ask a question, or use one of the suggested prompts.

The default preset targets `deepseek/deepseek-chat` through
`https://openrouter.ai/api/v1`. For local models, no API key is required when the
base URL points at `localhost` or `127.0.0.1`. Ollama and LM Studio may need their
CORS settings to allow requests from the page's origin.

The context sent to the model includes the capture summary, display filter, selected
packet, protocol mix, top conversations and endpoints, DNS/HTTP/TLS observations,
notable heuristic signals, marked packets/comments and a sample of visible packets.
For the selected frame it also includes conversation statistics, TCP handshake and
anomaly evidence, payload metrics, related frames and the exact conversation filter.
Raw payload previews are excluded unless you enable the option in AI settings.

Both AI surfaces also have a **◆ Triage** suggestion. It runs the local deterministic
detectors over the active capture first, adds the bounded findings (severity,
confidence, evidence frames, filters, entities and next pivots) to the model context,
and then asks the model to explain and correlate them. The detectors never call a
provider and the model is instructed to explain existing evidence rather than invent
new findings. In the map chat, the **◆** button in the chat header opens the Triage rail
directly.

Selecting a packet reveals the **Dossier** and **Deep dive** buttons above the chat.
Double-clicking a packet row (or using **Analyze → Packet Dossier**) also opens the
dossier, which is generated locally from the loaded capture: decoded layers and fields,
conversation context and direction, local findings, payload entropy/printability,
related frames and a copyable text summary. It never sends data to a model. **Deep
dive** asks the model for a structured, field-level analysis of that exact frame.

The model can request read-only packet data inside a fenced `pcap-tool` block:
`packet {no}`, `packets {filter, limit}`, `stream {no, limit}`, `range {from, to}` and
`expert {limit}`. Requests are executed locally against the loaded capture, shown as
cards with the exact data supplied to the model, and limited to two follow-up rounds.
The model can cite frames as `#12`; citations become clickable when the frame exists
in the active capture.

The model can request viewer actions inside a fenced `pcap-action` block:
`set_filter`, `clear_filter`, `select_packet`, `inspect_packet`, `mark_packet`,
`open_panel` and `follow_stream`. Suggested actions appear as cards and are never
applied without approval unless **Auto-apply suggested UI actions** is enabled.
`inspect_packet` selects the frame and opens its local dossier. Packet contents are
always treated as untrusted context, not as instructions to the model.

Chat history and the API key are stored only in this browser's `localStorage`. Use a
local provider for sensitive captures, and clear the key from AI settings when using
a shared machine.

## Limits

- Maximum capture size: **128 MB**
- Packet count: **no fixed limit**: every packet in a capture up to the size limit is
  parsed.
- Captures above 5,000 packets are decoded asynchronously in 1,500-packet chunks with
  progress in the status bar.
- The packet list is virtualized above 300 displayed rows, so only the visible rows are
  in the DOM.
- The 128 MB file guard is defined at the top of `static/pcap_viewer.js`.

## Using the viewer from JavaScript

The viewer exposes a small global API:

```js
// Open a File/Blob or a URL string.
openPcapFile(file, 'capture.pcap');
openPcapViewer('samples/sample.pcap');

// Close the active viewer.
closePcapViewer();

// Programmatic control.
PcapViewerApi.active();           // current viewer state
PcapViewerApi.setFilter('tcp.port == 443');
PcapViewerApi.queryPackets('dns', 20); // read-only, does not change the viewer filter
PcapViewerApi.selectNo(12);
PcapViewerApi.markNo(12, true);
PcapViewerApi.openPanel('conversations');
PcapViewerApi.openPanel('treemap');
PcapViewerApi.explainFilter('tcp && dns'); // local plain-language explanation
PcapViewerApi.openInvestigate();
PcapViewerApi.openFilterAssistant();
PcapViewerApi.decodeCapture(file, 'baseline.pcap')
  .then((capture) => { /* {name, format, bytes, packets}, parsed locally */ });

// AI analyst panel.
PcapAI.toggle();                  // open/close
PcapAI.open();
PcapAI.send('Summarize this capture');
PcapAI.parseActions(text);        // parse fenced pcap-action blocks
PcapAI.parseTools(text);          // parse fenced pcap-tool blocks
PcapAI.dossier(12);               // open the local packet dossier for #12
PcapAI.deepDive(12);              // request a deep AI analysis of #12
PcapAI.queryPackets('tcp', 10);   // read-only packet query
PcapAI.triage();                  // run local detectors, then ask for an explanation
PcapAI.providerSettings();        // open the shared provider dialog
PcapAI.isConfigured();            // true when a key or local endpoint is set
PcapAI.suggestFilter('DNS NXDOMAIN responses');
  // -> Promise { filter, rationale, terms, validation, model }
PcapAI.investigationNarrative(brief);
  // -> Promise { text, model, generatedAt }

// Investigation workspace.
const brief = PcapTriage.brief(capture);
  // { overview, hypotheses, ledger, timeline, graph, recommendations, integrity, ... }
PcapInvestigate.open();
PcapInvestigate.openFilterAssistant();
PcapInvestigate.briefMarkdown(brief);              // complete Markdown report
PcapInvestigate.briefHtml(brief);                  // standalone HTML report
PcapInvestigate.sanitizeDashes(text);
PcapInvestigate.citationCheck(narrativeText, brief); // { total, connected, outside, missing }

// Local triage, case and baseline comparison.
const analysis = PcapTriage.analyze(capture);       // { findings, stats, detectors, ... }
const currentSummary = PcapTriage.summarize(capture.packets, capture.name);
const baselineSummary = PcapTriage.summarize(baseline.packets, baseline.name);
PcapTriage.compare(currentSummary, baselineSummary, baseline.name); // novel entities
PcapTriage.setBenign(analysis.findings[0].fingerprint, true);       // persist a mark
PcapTriage.case.pin(analysis.findings[0], capture.name);            // pin finding + frames
PcapTriage.case.addPacketRef('capture.pcap', 12, 'Suspicious response');
PcapTriage.case.setNotes('Confirmed 60 second cadence.');
PcapTriage.case.exportMarkdown();                 // redacted Markdown string
PcapTriage.case.exportJson();                     // redacted JSON string
PcapTriage.case.download('md');                   // trigger a browser download
```

`PcapTriage.analyze()` expects the same decoded-capture shape returned by
`PcapViewerApi.decodeCapture()`. Detection is synchronous and deterministic; it does not
call a provider or persist anything except benign marks when you ask it to. The case is
stored under `pcapViewer.case.v1` and benign fingerprints under
`pcapViewer.triage.benign.v1`; both are browser-local.

The viewer also dispatches a `pcap:event` `CustomEvent` on `document` for integration
with other tools:

```js
document.addEventListener('pcap:event', (event) => {
  console.log(event.detail.type, event.detail.detail);
});
```

Event types include `ready`, `select`, `filter`, `field`, `mark`, `action`,
`dialog`, `capture` and `closed`.

## Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+O` | Open capture |
| `Ctrl+F` | Find packet |
| `Ctrl+G` | Go to packet |
| `Ctrl+M` | Mark/unmark packet |
| `Ctrl+I` | Toggle the AI analyst panel, or the map chat while the traffic map or triage is open |
| `Double-click packet` | Open the local packet dossier |
| `Ctrl+/` | Focus display filter |
| `Ctrl+=` / `Ctrl+-` / `Ctrl+0` | Zoom in / out / reset |
| `Ctrl+R` | Reload capture |
| `F1` | Display filter help |
| `Home` / `End` | First / last packet |
| `↑` / `↓` | Previous / next packet |
| `Esc` | Close triage, map chat, dialog or menu first; otherwise close the viewer |
