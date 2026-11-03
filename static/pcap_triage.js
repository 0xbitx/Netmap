
(function () {
    'use strict';

    var CASE_KEY = 'pcapViewer.case.v1';
    var BENIGN_KEY = 'pcapViewer.triage.benign.v1';
    var FRAME_EVIDENCE_MAX = 40;

    var SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
    var SEVERITY_LABEL = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

    var COMMON_PROTOCOLS = {
        TCP: 1, UDP: 1, TLS: 1, SSL: 1, HTTP: 1, DNS: 1, ARP: 1, RARP: 1,
        ICMP: 1, ICMPV6: 1, SSH: 1, NTP: 1, DHCP: 1, MDNS: 1, DATA: 1,
        FTP: 1, TELNET: 1, SMTP: 1, POP: 1, IMAP: 1,
        FRAME: 1, ETHERNET: 1, IPV4: 1, IPV6: 1, VLAN: 1
    };

    var PERIODIC_EXEMPT_PORTS = { 67: 1, 68: 1, 123: 1, 1900: 1, 5353: 1, 5355: 1 };

    var LATERAL_PORTS = {
        22: 'SSH', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB',
        3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM TLS', 1433: 'MSSQL',
        3306: 'MySQL', 5432: 'PostgreSQL', 5900: 'VNC'
    };

    var SERVICE_PORTS = {
        20: 1, 21: 1, 22: 1, 23: 1, 25: 1, 53: 1, 69: 1, 80: 1, 88: 1,
        110: 1, 123: 1, 135: 1, 137: 1, 138: 1, 139: 1, 143: 1, 161: 1,
        162: 1, 389: 1, 443: 1, 445: 1, 465: 1, 514: 1, 587: 1, 636: 1,
        993: 1, 995: 1, 1433: 1, 1521: 1, 2049: 1, 3306: 1, 3389: 1,
        5432: 1, 5900: 1, 5985: 1, 5986: 1, 6379: 1, 8080: 1, 8443: 1,
        9200: 1, 11211: 1, 27017: 1
    };

    var DETECTOR_LABELS = {
        beaconing: 'Beaconing',
        scan: 'Scan / fan-out',
        dns: 'DNS anomaly',
        exfiltration: 'Outbound asymmetry',
        credentials: 'Cleartext credentials',
        arp: 'ARP conflict',
        lateral: 'Lateral movement',
        rare: 'Rare protocol',
        longlived: 'Long-lived flow',
        correlation: 'Capture comparison'
    };

    function has(object, key) {
        return Object.prototype.hasOwnProperty.call(object, key);
    }

    function safeGet(key, fallback) {
        try {
            var raw = localStorage.getItem(key);
            if (!raw) return fallback;
            return JSON.parse(raw);
        } catch (e) {
            return fallback;
        }
    }

    function safeSet(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch (e) {
            return false;
        }
    }

    function clone(value) {
        try { return JSON.parse(JSON.stringify(value)); }
        catch (e) { return value; }
    }

    function asArray(value) {
        if (value == null) return [];
        return Array.isArray(value) ? value : [value];
    }

    function lower(value) {
        return String(value == null ? '' : value).toLowerCase();
    }

    function trimName(value) {
        return lower(value).replace(/\.$/, '').trim();
    }

    function isIp(value) {
        var text = String(value == null ? '' : value);
        return /^(\d{1,3}\.){3}\d{1,3}$/.test(text) || text.indexOf(':') >= 0;
    }

    function isUsefulHost(host) {
        var h = trimName(host);
        if (!h) return false;
        if (h === '0.0.0.0' || h === '255.255.255.255' || h === '::' || h === '::1') return false;
        if (/^224\./.test(h) || /^239\./.test(h)) return false;
        if (/^ff[0-9a-f]{2}:/.test(h) || h === 'ff02::1' || h === 'ff02::2') return false;
        if (/^fe80:/.test(h)) return false;
        return true;
    }

    function isUsefulMac(mac) {
        var m = lower(mac);
        if (!m || m === 'ff:ff:ff:ff:ff:ff' || m === '00:00:00:00:00:00') return false;
        var first = parseInt(m.split(':')[0], 16);
        return !isFinite(first) || (first & 1) === 0;
    }

    function plural(n, one, many) {
        return n + ' ' + (n === 1 ? one : (many || one + 's'));
    }

    function fmtBytes(bytes) {
        var n = Number(bytes) || 0;
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10 * 1024 ? 1 : 0) + ' KB';
        if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0) + ' MB';
        return (n / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
    }

    function fmtSeconds(seconds) {
        var s = Math.max(0, Number(seconds) || 0);
        if (s < 1) return Math.round(s * 1000) + ' ms';
        if (s < 60) return (Math.round(s * 10) / 10) + ' s';
        if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.round(s % 60) + 's';
        return Math.floor(s / 3600) + 'h ' + Math.round((s % 3600) / 60) + 'm';
    }

    function fields(packet) {
        return (packet && packet.fields) || {};
    }

    function field(packet, key) {
        return fields(packet)[key];
    }

    function packetTime(packet) {
        if (!packet) return 0;
        if (packet.time != null && isFinite(packet.time)) return Number(packet.time);
        if (packet.rel != null && isFinite(packet.rel)) return Number(packet.rel);
        return Number(packet.no) || 0;
    }

    function packetNo(packet) {
        return packet && packet.no != null ? packet.no : 0;
    }

    function packetIndex(packet, fallback) {
        if (packet && packet.index != null) return Number(packet.index);
        if (packet && packet.no != null) return Math.max(0, Number(packet.no) - 1);
        return fallback || 0;
    }

    function srcHost(packet) {
        var f = fields(packet);
        return f['ip.src'] || f['ipv6.src'] || (isIp(packet && packet.dec && packet.dec.src) ? packet.dec.src : '') || '';
    }

    function dstHost(packet) {
        var f = fields(packet);
        return f['ip.dst'] || f['ipv6.dst'] || (isIp(packet && packet.dec && packet.dec.dst) ? packet.dec.dst : '') || '';
    }

    function addrField(packet) {
        var f = fields(packet);
        if (f['ipv6.src'] || f['ipv6.dst']) return 'ipv6.addr';
        if (f['ip.src'] || f['ip.dst']) return 'ip.addr';
        if (f['arp.src.proto_ipv4'] || f['arp.dst.proto_ipv4']) return 'arp';
        return 'ip.addr';
    }

    function quoteHost(host, always) {
        var h = String(host == null ? '' : host);
        if (always || h.indexOf(':') >= 0 || /[^A-Za-z0-9_.\-:/]/.test(h)) {
            return '"' + h.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
        }
        return h;
    }

    function hostFilter(packet, host) {
        if (!host) return '';
        return addrField(packet) + ' == ' + quoteHost(host, host.indexOf(':') >= 0);
    }

    function frameFilter(nos) {
        var seen = {};
        var parts = [];
        for (var i = 0; i < nos.length && parts.length < 24; i++) {
            var no = Number(nos[i]);
            if (!isFinite(no) || seen[no]) continue;
            seen[no] = true;
            parts.push('frame.number == ' + no);
        }
        return parts.join(' || ');
    }

    function conversationShape(packet) {
        var hostA = srcHost(packet);
        var hostB = dstHost(packet);
        var proto = lower(packet && packet.transport);
        if (!hostA || !hostB || (proto !== 'tcp' && proto !== 'udp')) return null;
        var portA = packet.srcport === '' || packet.srcport == null ? '' : String(packet.srcport);
        var portB = packet.dstport === '' || packet.dstport == null ? '' : String(packet.dstport);
        var first = { host: hostA, port: portA };
        var second = { host: hostB, port: portB };
        var flip = hostA > hostB || (hostA === hostB && Number(portA) > Number(portB));
        var a = flip ? second : first;
        var b = flip ? first : second;
        return {
            proto: proto,
            a: a,
            b: b,
            key: proto + '|' + a.host + ':' + a.port + '|' + b.host + ':' + b.port,
            initiator: hostA,
            responder: hostB,
            initiatorPort: portA,
            responderPort: portB
        };
    }

    function conversationFilter(shape) {
        if (!shape) return '';
        var host = shape.a.host || shape.b.host;
        var addressField = host && host.indexOf(':') >= 0 ? 'ipv6.addr' : 'ip.addr';
        var legs = [addressField + ' == ' + quoteHost(shape.a.host, host.indexOf(':') >= 0),
            addressField + ' == ' + quoteHost(shape.b.host, host.indexOf(':') >= 0)];
        if (shape.proto === 'tcp' || shape.proto === 'udp') {
            var port = shape.a.port || shape.b.port;
            if (port) legs.push(shape.proto + '.port == ' + port);
        }
        return legs.filter(Boolean).join(' && ');
    }

    function payloadText(packet, max) {
        if (!packet || !packet.payload || !packet.bytes) return '';
        var start = Number(packet.payload.off) || 0;
        var end = Math.min(Number(packet.payload.end) || 0, start + (max || 4096));
        if (end <= start || start < 0 || end > packet.bytes.length) return '';
        var out = '';
        for (var i = start; i < end; i++) out += String.fromCharCode(packet.bytes[i]);
        return out;
    }

    function entropy(text) {
        var value = String(text || '');
        if (!value.length) return 0;
        var counts = {};
        for (var i = 0; i < value.length; i++) {
            var ch = value.charAt(i);
            counts[ch] = (counts[ch] || 0) + 1;
        }
        var e = 0;
        for (var key in counts) {
            if (!has(counts, key)) continue;
            var p = counts[key] / value.length;
            e -= p * (Math.log(p) / Math.LN2);
        }
        return e;
    }

    function mean(values) {
        if (!values.length) return 0;
        var total = 0;
        for (var i = 0; i < values.length; i++) total += values[i];
        return total / values.length;
    }

    function stddev(values) {
        if (values.length < 2) return 0;
        var avg = mean(values);
        var total = 0;
        for (var i = 0; i < values.length; i++) {
            var d = values[i] - avg;
            total += d * d;
        }
        return Math.sqrt(total / (values.length - 1));
    }

    function unique(arr) {
        var seen = {};
        var out = [];
        for (var i = 0; i < arr.length; i++) {
            var value = String(arr[i] == null ? '' : arr[i]);
            if (!value || seen[value]) continue;
            seen[value] = true;
            out.push(value);
        }
        return out;
    }

    function evidenceFor(packet, index, label) {
        return {
            no: packetNo(packet),
            index: index,
            label: label || (packet && packet.dec ? (packet.dec.proto || '') : ''),
            time: packetTime(packet)
        };
    }

    function finding(spec) {
        var out = {
            detector: spec.detector,
            key: spec.key || spec.title || '',
            title: spec.title || 'Finding',
            severity: spec.severity || 'info',
            confidence: Math.max(0, Math.min(100, Math.round(spec.confidence == null ? 50 : spec.confidence))),
            summary: spec.summary || '',
            detail: spec.detail || '',
            evidence: spec.evidence || [],
            filter: spec.filter || '',
            entities: spec.entities || {},
            nextPivot: spec.nextPivot || '',
            meta: spec.meta || {},
            comparison: !!spec.comparison
        };
        out.frames = unique(out.evidence.map(function (item) { return item.no; })).map(Number);
        return out;
    }

    function captureId(viewer) {
        var packets = (viewer && viewer.packets) || [];
        var firstNo = packets.length ? packetNo(packets[0]) : 0;
        var lastNo = packets.length ? packetNo(packets[packets.length - 1]) : 0;
        return String((viewer && viewer.name) || 'capture') + '|' + packets.length + '|' + firstNo + '-' + lastNo;
    }

    function fingerprint(viewer, item) {
        var first = item.evidence && item.evidence.length ? item.evidence[0].no : 0;
        var last = item.evidence && item.evidence.length ? item.evidence[item.evidence.length - 1].no : 0;
        return captureId(viewer) + '|' + item.detector + '|' + (item.key || item.title) + '|' + first + '|' + last;
    }

    function readBenign() {
        var value = safeGet(BENIGN_KEY, {});
        return value && typeof value === 'object' ? value : {};
    }

    function isBenign(fp) {
        return !!readBenign()[fp];
    }

    function setBenign(fp, on) {
        var map = readBenign();
        if (on) map[fp] = new Date().toISOString();
        else delete map[fp];
        safeSet(BENIGN_KEY, map);
        return !!on;
    }

    function clearBenign() {
        safeSet(BENIGN_KEY, {});
    }

    function detectorBeaconing(packets) {
        var groups = {};
        var dnsGroups = {};

        function addEvent(map, key, item) {
            if (!map[key]) map[key] = { events: [], key: key };
            map[key].events.push(item);
        }

        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var f = fields(p);
            var proto = lower(p.transport);
            var src = srcHost(p);
            var dst = dstHost(p);
            if (!src || !dst) continue;
            var dport = Number(p.dstport);

            if (proto === 'tcp') {
                if (Number(f['tcp.flags.syn']) !== 1 || Number(f['tcp.flags.ack']) !== 0) continue;
                if (PERIODIC_EXEMPT_PORTS[dport]) continue;
                addEvent(groups, 'tcp|' + src + '|' + dst + '|' + dport, {
                    packet: p, index: i, time: packetTime(p), size: p.len
                });
            } else if (proto === 'udp') {
                if (dport === 53) {
                    var names = unique(asArray(f['dns.qry.name']).map(trimName));
                    if (Number(f['dns.flags.response']) === 0) {
                        for (var n = 0; n < names.length; n++) {
                            addEvent(dnsGroups, 'dns|' + src + '|' + names[n], {
                                packet: p, index: i, time: packetTime(p), size: p.len, domain: names[n]
                            });
                        }
                    }
                    continue;
                }
                if (PERIODIC_EXEMPT_PORTS[dport]) continue;
                addEvent(groups, 'udp|' + src + '|' + dst + '|' + dport, {
                    packet: p, index: i, time: packetTime(p), size: p.len
                });
            }
        }

        var findings = [];

        function evaluate(entry, kind) {
            var events = entry.events.slice().sort(function (a, b) { return a.time - b.time; });
            if (events.length < 6) return;
            var times = [];
            var sizes = [];
            for (var e = 0; e < events.length; e++) {
                if (!times.length || events[e].time - times[times.length - 1] > 0.05) {
                    times.push(events[e].time);
                    sizes.push(events[e].size || 0);
                }
            }
            if (times.length < 6) return;
            var intervals = [];
            for (var t = 1; t < times.length; t++) {
                var delta = times[t] - times[t - 1];
                if (delta > 0.05) intervals.push(delta);
            }
            if (intervals.length < 5) return;
            var avg = mean(intervals);
            var sd = stddev(intervals);
            var cv = avg > 0 ? sd / avg : 1;
            if (avg < 1 || avg > 7200 || cv > 0.22) return;
            var span = times[times.length - 1] - times[0];
            if (span < avg * 4) return;

            var sizeAvg = mean(sizes);
            var sizeCv = sizeAvg > 0 ? stddev(sizes) / sizeAvg : 0;
            var confidence = 58 + Math.min(22, times.length * 2) + Math.round((0.22 - cv) * 110);
            if (sizeCv > 0.65) confidence -= 12;
            confidence = Math.max(45, Math.min(97, confidence));

            var evidence = [];
            var take = Math.min(events.length, 24);
            for (var k = 0; k < take; k++) {
                var at = take === events.length ? k :
                    Math.round(k * (events.length - 1) / Math.max(1, take - 1));
                var item = events[at];
                evidence.push(evidenceFor(item.packet, item.index,
                    'event at +' + fmtSeconds(item.time - times[0])));
            }

            var label;
            var filter;
            var entities;
            var key;
            var meta;
            if (kind === 'dns') {
                var domain = events[0].domain;
                label = domain + ' via DNS';
                filter = 'dns && dns.qry.name == "' + domain + '"';
                entities = {
                    hosts: unique([srcHost(events[0].packet), dstHost(events[0].packet)]),
                    domains: [domain],
                    ports: [53],
                    protocols: ['DNS']
                };
                key = 'dns|' + srcHost(events[0].packet) + '|' + domain;
                meta = { source: srcHost(events[0].packet), domain: domain, meanInterval: avg, jitter: cv };
            } else {
                var first = events[0].packet;
                var shape = conversationShape(first);
                var dportLabel = first.dstport === '' ? '' : ':' + first.dstport;
                label = srcHost(first) + ' → ' + dstHost(first) + dportLabel;
                filter = shape ? conversationFilter(shape) :
                    (hostFilter(first, dstHost(first)) + ' && ' + (first.transport || 'ip'));
                entities = {
                    hosts: unique([srcHost(first), dstHost(first)]),
                    ports: unique([first.dstport]),
                    protocols: unique([String(first.dec && first.dec.proto || first.transport || '')])
                };
                key = 'flow|' + srcHost(first) + '|' + dstHost(first) + '|' + first.dstport;
                meta = {
                    source: srcHost(first),
                    destination: dstHost(first),
                    port: Number(first.dstport),
                    meanInterval: avg,
                    jitter: cv
                };
            }

            findings.push(finding({
                detector: 'beaconing',
                key: key,
                title: 'Periodic beaconing to ' + label,
                severity: times.length >= 8 && cv <= 0.09 ? 'high' : 'medium',
                confidence: confidence,
                summary: plural(times.length, 'event') + ' at a mean interval of ' +
                    fmtSeconds(avg) + ' with ' + Math.round(cv * 100) + '% jitter.',
                detail: 'The same source repeatedly contacts this destination on a regular cadence. ' +
                    'Mean interval ' + fmtSeconds(avg) + ', standard deviation ' + fmtSeconds(sd) +
                    ', coefficient of variation ' + Math.round(cv * 100) + '%.' +
                    (sizeCv > 0.65 ? ' Packet sizes vary widely, which lowers confidence.' : ''),
                evidence: evidence,
                filter: filter,
                entities: entities,
                nextPivot: 'Compare the cadence with the packet payloads and check whether the destination is sanctioned.',
                meta: meta
            }));
        }

        for (var g in groups) if (has(groups, g)) evaluate(groups[g], 'flow');
        for (var d in dnsGroups) if (has(dnsGroups, d)) evaluate(dnsGroups[d], 'dns');

        return findings.slice(0, 10);
    }

    function detectorScan(packets) {
        var bySource = {};
        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var f = fields(p);
            if (lower(p.transport) !== 'tcp') continue;
            if (Number(f['tcp.flags.syn']) !== 1 || Number(f['tcp.flags.ack']) !== 0) continue;
            var src = srcHost(p);
            var dst = dstHost(p);
            if (!src || !dst) continue;
            var source = bySource[src] || (bySource[src] = {
                src: src, events: [], dests: {}, ports: {}, pairs: {}
            });
            source.events.push({ packet: p, index: i });
            source.dests[dst] = true;
            source.ports[String(p.dstport)] = true;
            var pair = source.pairs[dst] || (source.pairs[dst] = { dst: dst, ports: {}, events: [] });
            pair.ports[String(p.dstport)] = true;
            pair.events.push({ packet: p, index: i });
        }

        var findings = [];
        for (var srcKey in bySource) {
            if (!has(bySource, srcKey)) continue;
            var source = bySource[srcKey];
            var targetPorts = Object.keys(source.ports);
            var targets = Object.keys(source.dests);

            if (targets.length >= 8 && source.events.length >= 8) {
                var fanEvidence = [];
                for (var e = 0; e < source.events.length && fanEvidence.length < 24; e++) {
                    var fp = source.events[e];
                    fanEvidence.push(evidenceFor(fp.packet, fp.index, 'SYN → ' + dstHost(fp.packet) + ':' + fp.packet.dstport));
                }
                findings.push(finding({
                    detector: 'scan',
                    key: 'fanout|' + source.src,
                    title: 'Fan-out from ' + source.src + ' to ' + plural(targets.length, 'host'),
                    severity: targets.length >= 15 ? 'high' : 'medium',
                    confidence: Math.min(96, 62 + targets.length * 2),
                    summary: plural(source.events.length, 'connection attempt') + ' against ' +
                        plural(targets.length, 'destination host') + ' and ' + plural(targetPorts.length, 'port') + '.',
                    detail: 'One source opened connection attempts to many destinations. ' +
                        'Targets include ' + targets.slice(0, 12).join(', ') + (targets.length > 12 ? ' …' : '') + '.',
                    evidence: fanEvidence,
                    filter: 'ip.src == ' + quoteHost(source.src, source.src.indexOf(':') >= 0) +
                        ' && tcp.flags.syn == 1 && tcp.flags.ack == 0',
                    entities: {
                        hosts: [source.src].concat(targets.slice(0, 16)),
                        ports: targetPorts.slice(0, 20).map(Number),
                        protocols: ['TCP']
                    },
                    nextPivot: 'Look for successful handshakes and the first service that accepted a connection.',
                    meta: { source: source.src, targets: targets.length, ports: targetPorts.length }
                }));
            }

            var pairList = [];
            for (var dstKey in source.pairs) if (has(source.pairs, dstKey)) pairList.push(source.pairs[dstKey]);
            pairList.sort(function (a, b) { return Object.keys(b.ports).length - Object.keys(a.ports).length; });
            for (var pi = 0; pi < Math.min(2, pairList.length); pi++) {
                var pair = pairList[pi];
                var pairPorts = Object.keys(pair.ports);
                if (pairPorts.length < 10 || pair.events.length < 10) continue;
                var pEvidence = [];
                for (var pe = 0; pe < pair.events.length && pEvidence.length < 24; pe++) {
                    var event = pair.events[pe];
                    pEvidence.push(evidenceFor(event.packet, event.index, 'port ' + event.packet.dstport));
                }
                findings.push(finding({
                    detector: 'scan',
                    key: 'ports|' + source.src + '|' + pair.dst,
                    title: 'Port scan from ' + source.src + ' to ' + pair.dst,
                    severity: pairPorts.length >= 20 ? 'high' : 'medium',
                    confidence: Math.min(97, 66 + pairPorts.length * 2),
                    summary: plural(pairPorts.length, 'distinct port') + ' probed on one host with ' +
                        plural(pair.events.length, 'SYN') + '.',
                    detail: 'Ports include ' + pairPorts.slice(0, 24).join(', ') +
                        (pairPorts.length > 24 ? ' …' : '') + '.',
                    evidence: pEvidence,
                    filter: 'ip.src == ' + quoteHost(source.src, source.src.indexOf(':') >= 0) +
                        ' && ip.dst == ' + quoteHost(pair.dst, pair.dst.indexOf(':') >= 0) +
                        ' && tcp.flags.syn == 1 && tcp.flags.ack == 0',
                    entities: {
                        hosts: [source.src, pair.dst],
                        ports: pairPorts.slice(0, 24).map(Number),
                        protocols: ['TCP']
                    },
                    nextPivot: 'Check for RST responses and for the first port that completed a handshake.',
                    meta: { source: source.src, destination: pair.dst, ports: pairPorts.length }
                }));
            }
        }
        findings.sort(function (a, b) { return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.confidence - a.confidence; });
        return findings.slice(0, 12);
    }

    function detectorDns(packets) {
        var queries = [];
        var nx = {};
        var byParent = {};
        var txt = [];

        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var f = fields(p);
            var names = unique(asArray(f['dns.qry.name']).map(trimName).filter(Boolean));
            if (!names.length) continue;
            var response = Number(f['dns.flags.response']) === 1;
            var rcode = Number(f['dns.flags.rcode']);
            if (!response) {
                for (var n = 0; n < names.length; n++) {
                    var name = names[n];
                    queries.push({ packet: p, index: i, name: name, qtype: Number(f['dns.qry.type']) });
                    var labels = name.split('.');
                    var parent = labels.slice(-2).join('.');
                    if (!byParent[parent]) byParent[parent] = { parent: parent, names: {}, events: [] };
                    byParent[parent].names[name] = true;
                    byParent[parent].events.push({ packet: p, index: i, name: name });
                }
            }
            if (response && rcode === 3) {
                for (var x = 0; x < names.length; x++) {
                    var nxName = names[x];
                    if (!nx[nxName]) nx[nxName] = { name: nxName, events: [] };
                    nx[nxName].events.push({ packet: p, index: i });
                }
            }
            if (response) {
                var answers = asArray(f['dns.answers']);
                for (var a = 0; a < answers.length; a++) {
                    if (!/^TXT\b/i.test(String(answers[a]))) continue;
                    var parentTxt = names[0].split('.').slice(-2).join('.');
                    txt.push({ packet: p, index: i, name: names[0], parent: parentTxt });
                }
            }
        }

        var findings = [];

        for (var nxName in nx) {
            if (!has(nx, nxName)) continue;
            var nxEntry = nx[nxName];
            if (nxEntry.events.length < 4) continue;
            var nxEvidence = [];
            for (var ne = 0; ne < nxEntry.events.length && nxEvidence.length < 16; ne++) {
                nxEvidence.push(evidenceFor(nxEntry.events[ne].packet, nxEntry.events[ne].index, 'NXDOMAIN'));
            }
            findings.push(finding({
                detector: 'dns',
                key: 'nxdomain|' + nxEntry.name,
                title: 'NXDOMAIN burst for ' + nxEntry.name,
                severity: nxEntry.events.length >= 8 ? 'medium' : 'low',
                confidence: Math.min(90, 55 + nxEntry.events.length * 3),
                summary: plural(nxEntry.events.length, 'NXDOMAIN response') + ' for the same name.',
                detail: 'Repeated failures for one name can indicate domain generation or a misconfigured beacon.',
                evidence: nxEvidence,
                filter: 'dns.flags.rcode == 3 && dns.qry.name == "' + nxEntry.name + '"',
                entities: { domains: [nxEntry.name], protocols: ['DNS'] },
                nextPivot: 'Pivot to the queries and compare their timing with any resolved domains.',
                meta: { domain: nxEntry.name }
            }));
        }

        for (var parentKey in byParent) {
            if (!has(byParent, parentKey)) continue;
            var group = byParent[parentKey];
            var names = Object.keys(group.names);
            if (names.length < 8) continue;
            var lengths = names.map(function (item) { return item.length; });
            var avgLength = mean(lengths);
            var maxLabel = 0;
            var entropies = [];
            for (var q = 0; q < names.length; q++) {
                var parts = names[q].split('.');
                for (var l = 0; l < parts.length; l++) maxLabel = Math.max(maxLabel, parts[l].length);
                entropies.push(entropy(parts[0] || ''));
            }
            var avgEntropy = mean(entropies);
            if (avgLength < 30 && maxLabel < 24 && avgEntropy < 3.4) continue;
            var dnsEvidence = [];
            for (var de = 0; de < group.events.length && dnsEvidence.length < 20; de++) {
                dnsEvidence.push(evidenceFor(group.events[de].packet, group.events[de].index, group.events[de].name));
            }
            findings.push(finding({
                detector: 'dns',
                key: 'tunnel|' + group.parent,
                title: 'Possible DNS tunneling via ' + group.parent,
                severity: names.length >= 12 && avgLength >= 40 ? 'high' : 'medium',
                confidence: Math.min(96, 55 + names.length * 2 + Math.round(avgEntropy * 4)),
                summary: plural(names.length, 'unique subdomain') + ' under one parent, average name length ' +
                    Math.round(avgLength) + ', label entropy ' + (Math.round(avgEntropy * 100) / 100) + ' bits/char.',
                detail: 'High-entropy, long, unique labels under a single parent are consistent with DNS tunneling. ' +
                    'This is a shape signal, not proof: verify the payload and resolver logs.',
                evidence: dnsEvidence,
                filter: 'dns && dns.qry.name contains "' + group.parent + '"',
                entities: { domains: names.slice(0, 24).concat([group.parent]), protocols: ['DNS'] },
                nextPivot: 'Compare query/response sizes and look for TXT or NULL records carrying data.',
                meta: { domain: group.parent, names: names.length, avgLength: avgLength, entropy: avgEntropy }
            }));
        }

        if (txt.length >= 3) {
            var txtEvidence = [];
            for (var te = 0; te < txt.length && txtEvidence.length < 16; te++) {
                txtEvidence.push(evidenceFor(txt[te].packet, txt[te].index, 'TXT ' + txt[te].name));
            }
            findings.push(finding({
                detector: 'dns',
                key: 'txt|' + txt[0].parent,
                title: 'TXT record activity for ' + txt[0].parent,
                severity: 'medium',
                confidence: 65,
                summary: plural(txt.length, 'TXT answer') + ' observed for one domain.',
                detail: 'TXT records are sometimes used to carry command-and-control data. Confirm the record contents before drawing a conclusion.',
                evidence: txtEvidence,
                filter: 'dns && dns.qry.name contains "' + txt[0].parent + '"',
                entities: { domains: [txt[0].parent], protocols: ['DNS'] },
                nextPivot: 'Inspect the TXT record values and response sizes.',
                meta: { domain: txt[0].parent }
            }));
        }

        findings.sort(function (a, b) { return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.confidence - a.confidence; });
        return findings.slice(0, 12);
    }

    function detectorExfiltration(packets) {
        var groups = {};
        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var shape = conversationShape(p);
            if (!shape) continue;
            var dport = Number(p.dstport);
            var sport = Number(p.srcport);
            if (PERIODIC_EXEMPT_PORTS[dport] || PERIODIC_EXEMPT_PORTS[sport]) continue;
            var group = groups[shape.key] || (groups[shape.key] = {
                shape: shape,
                initiator: srcHost(p),
                bytesOut: 0,
                bytesIn: 0,
                packets: 0,
                first: packetTime(p),
                last: packetTime(p),
                outFrames: []
            });
            var bytes = Number(p.len) || 0;
            group.packets++;
            group.last = Math.max(group.last, packetTime(p));
            group.first = Math.min(group.first, packetTime(p));
            if (srcHost(p) === group.initiator) {
                group.bytesOut += bytes;
                group.outFrames.push({ packet: p, index: i, len: bytes });
            } else {
                group.bytesIn += bytes;
            }
        }

        var findings = [];
        for (var key in groups) {
            if (!has(groups, key)) continue;
            var item = groups[key];
            var ratio = item.bytesOut / Math.max(1, item.bytesIn);
            if (item.bytesOut < 256 * 1024 || ratio < 6 || item.packets < 12) continue;
            var outFrames = item.outFrames.slice().sort(function (a, b) { return b.len - a.len; }).slice(0, 10);
            outFrames.sort(function (a, b) { return a.index - b.index; });
            var evidence = [];
            for (var o = 0; o < outFrames.length; o++) {
                evidence.push(evidenceFor(outFrames[o].packet, outFrames[o].index, fmtBytes(outFrames[o].len) + ' outbound'));
            }
            var outHost = item.shape.initiator;
            var inHost = item.shape.responder;
            var serverPort = item.shape.responderPort || item.shape.initiatorPort;
            findings.push(finding({
                detector: 'exfiltration',
                key: 'asym|' + key,
                title: 'Large outbound transfer to ' + inHost + (serverPort ? ':' + serverPort : ''),
                severity: item.bytesOut >= 5 * 1024 * 1024 && ratio >= 10 ? 'high' : 'medium',
                confidence: Math.min(95, 55 + Math.round(Math.min(20, ratio)) + Math.round(Math.min(20, item.bytesOut / (1024 * 1024) * 4))),
                summary: fmtBytes(item.bytesOut) + ' outbound versus ' + fmtBytes(item.bytesIn) +
                    ' inbound (' + (ratio >= 1000 ? '>1000' : Math.round(ratio * 10) / 10) + '× asymmetry) over ' +
                    fmtSeconds(item.last - item.first) + '.',
                detail: 'The initiator sent far more data than it received. This can be a legitimate upload, so confirm the destination and content before treating it as exfiltration.',
                evidence: evidence,
                filter: conversationFilter(item.shape),
                entities: {
                    hosts: [outHost, inHost],
                    ports: serverPort ? [Number(serverPort)] : [],
                    protocols: [item.shape.proto.toUpperCase()]
                },
                nextPivot: 'Follow the outbound stream and inspect the payload type and destination reputation.',
                meta: {
                    source: outHost, destination: inHost, bytesOut: item.bytesOut,
                    bytesIn: item.bytesIn, ratio: ratio
                }
            }));
        }
        findings.sort(function (a, b) { return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.confidence - a.confidence; });
        return findings.slice(0, 10);
    }

    function detectorCredentials(packets) {
        var grouped = {};
        var ftpUsers = {};

        function add(kind, username, packet, index, detail) {
            var shape = conversationShape(packet);
            var keyBase = (shape ? shape.key : String(packet.no)) + '|' + kind + '|' + lower(username || '');
            var entry = grouped[keyBase];
            if (!entry) {
                entry = grouped[keyBase] = {
                    kind: kind,
                    username: username || '',
                    packet: packet,
                    index: index,
                    shape: shape,
                    evidence: [],
                    detail: detail || ''
                };
            }
            if (entry.evidence.length < 12) {
                entry.evidence.push(evidenceFor(packet, index, kind + (username ? ' user=' + username : '')));
            }
        }

        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            if (lower(p.transport) !== 'tcp') continue;
            var text = payloadText(p, 4096);
            if (!text) continue;
            var shape = conversationShape(p);
            var convKey = shape ? shape.key : String(p.no);
            var sport = Number(p.srcport);
            var dport = Number(p.dstport);

            var basic = /Authorization\s*:\s*Basic\s+([A-Za-z0-9+/=]+)/i.exec(text);
            if (basic) {
                var decoded = '';
                try { decoded = atob(basic[1]); } catch (e) { decoded = ''; }
                var user = decoded ? decoded.split(':')[0] : '';
                add('HTTP Basic', user, p, i, 'HTTP Basic credentials are base64, not encrypted.');
            }

            var isHttp = /(?:^|\r?\n)(?:GET|POST|PUT|PATCH|DELETE)\s+\S+\s+HTTP\//i.test(text) ||
                /(?:^|\r?\n)HTTP\/\d\.\d\s+\d{3}/i.test(text) ||
                /content-type\s*:\s*application\/x-www-form-urlencoded/i.test(text);
            if (isHttp) {
                var pass = /(?:^|[&\r\n])(?:password|passwd|pwd|pass)=([^&\s\r\n]+)/i.exec(text);
                if (pass) {
                    var userMatch = /(?:^|[&\r\n])(?:username|user|login|email)=([^&\s\r\n]+)/i.exec(text);
                    var formUser = '';
                    if (userMatch) {
                        try { formUser = decodeURIComponent(userMatch[1].replace(/\+/g, ' ')); }
                        catch (e) { formUser = userMatch[1]; }
                    }
                    add('HTTP form', formUser, p, i,
                        'A password field was sent over unencrypted HTTP.');
                }
            }

            if (dport === 21 || sport === 21) {
                var userLine = /(?:^|\r?\n)USER\s+(\S+)/i.exec(text);
                if (userLine) ftpUsers[convKey] = userLine[1];
                var passLine = /(?:^|\r?\n)PASS\s+(\S+)/i.exec(text);
                if (passLine) {
                    add('FTP', ftpUsers[convKey] || '', p, i,
                        'FTP sends the password in clear text.');
                }
            }

            if ((dport === 23 || sport === 23) && /(?:login|username|password)\s*:/i.test(text)) {
                add('Telnet', '', p, i, 'A Telnet login prompt exposes the session in clear text.');
            }
        }

        var findings = [];
        for (var key in grouped) {
            if (!has(grouped, key)) continue;
            var item = grouped[key];
            var severity = item.kind === 'Telnet' ? 'medium' : 'high';
            var confidence = item.kind === 'HTTP Basic' ? 95 :
                item.kind === 'FTP' ? 92 : item.kind === 'HTTP form' ? 88 : 65;
            var hostLabel = item.shape ?
                (item.shape.responder + (item.shape.responderPort ? ':' + item.shape.responderPort : '')) :
                (dstHost(item.packet) || 'remote host');
            var userLabel = item.username ? ' for user "' + item.username + '"' : '';
            findings.push(finding({
                detector: 'credentials',
                key: 'cred|' + key,
                title: 'Cleartext ' + item.kind + ' credentials' + userLabel,
                severity: severity,
                confidence: confidence,
                summary: item.kind + ' credentials' + userLabel + ' were sent in cleartext to ' + hostLabel + '.',
                detail: item.detail + ' The password value is deliberately redacted here and is never stored in the case file.',
                evidence: item.evidence,
                filter: item.shape ? conversationFilter(item.shape) :
                    (hostFilter(item.packet, dstHost(item.packet)) + ' && tcp'),
                entities: {
                    hosts: item.shape ? [item.shape.initiator, item.shape.responder] : unique([srcHost(item.packet), dstHost(item.packet)]),
                    ports: item.shape ? unique([item.shape.responderPort, item.shape.initiatorPort]).map(Number) : [],
                    protocols: ['TCP', item.kind]
                },
                nextPivot: 'Follow the stream, confirm what was exposed, and rotate the credential.',
                meta: { kind: item.kind, username: item.username, redacted: true }
            }));
        }
        findings.sort(function (a, b) { return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.confidence - a.confidence; });
        return findings.slice(0, 12);
    }

    function detectorArp(packets) {
        var byIp = {};
        var byMac = {};
        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var f = fields(p);
            var ip = f['arp.src.proto_ipv4'];
            var mac = f['arp.src.hw_mac'];
            if (!ip || !mac) continue;
            mac = lower(mac);
            if (!isUsefulMac(mac)) continue;
            var entry = byIp[ip] || (byIp[ip] = { ip: ip, macs: {}, events: [] });
            if (!entry.macs[mac]) entry.macs[mac] = { mac: mac, events: [] };
            entry.macs[mac].events.push({ packet: p, index: i });
            entry.events.push({ packet: p, index: i, mac: mac });
            var claim = byMac[mac] || (byMac[mac] = { mac: mac, ips: {}, events: [] });
            claim.ips[ip] = true;
            claim.events.push({ packet: p, index: i, ip: ip });
        }

        var findings = [];
        for (var ipKey in byIp) {
            if (!has(byIp, ipKey)) continue;
            var entry = byIp[ipKey];
            var macs = Object.keys(entry.macs);
            if (macs.length >= 2) {
                var evidence = [];
                var claims = [];
                for (var m = 0; m < macs.length; m++) {
                    var macEntry = entry.macs[macs[m]];
                    claims.push(macs[m] + ' (' + plural(macEntry.events.length, 'claim') + ')');
                    for (var e = 0; e < macEntry.events.length && e < 3; e++) {
                        evidence.push(evidenceFor(macEntry.events[e].packet, macEntry.events[e].index, 'claimed by ' + macs[m]));
                    }
                }
                findings.push(finding({
                    detector: 'arp',
                    key: 'conflict|' + entry.ip,
                    title: 'ARP conflict for ' + entry.ip,
                    severity: 'high',
                    confidence: entry.events.length >= 4 ? 88 : 70,
                    summary: plural(macs.length, 'MAC address', 'MAC addresses') + ' claimed the same IP: ' + claims.join(', ') + '.',
                    detail: 'More than one MAC answered for one IPv4 address. Verify whether this is expected failover, a proxy ARP, or spoofing.',
                    evidence: evidence,
                    filter: 'arp.src.proto_ipv4 == ' + quoteHost(entry.ip, false),
                    entities: { hosts: [entry.ip], macs: macs, protocols: ['ARP'] },
                    nextPivot: 'Map both MACs to switch ports and look for a gratuitous ARP immediately before the change.',
                    meta: { ip: entry.ip, macs: macs }
                }));
            }
        }

        for (var macKey in byMac) {
            if (!has(byMac, macKey)) continue;
            var claim = byMac[macKey];
            var claimedIps = Object.keys(claim.ips);
            if (claimedIps.length < 5) continue;
            findings.push(finding({
                detector: 'arp',
                key: 'manyip|' + macKey,
                title: 'One MAC is claiming many addresses',
                severity: 'medium',
                confidence: 66,
                summary: macKey + ' claimed ' + plural(claimedIps.length, 'IPv4 address') +
                    ' with ' + plural(claim.events.length, 'ARP sender claim') + '.',
                detail: 'One MAC answering for many addresses can be normal proxy ARP or an attempt to attract traffic. Correlate it with the ARP conflicts and the switch MAC table.',
                evidence: claim.events.slice(0, 12).map(function (item) {
                    return evidenceFor(item.packet, item.index, 'claim for ' + item.ip);
                }),
                filter: 'arp.src.hw_mac == ' + quoteHost(macKey, true),
                entities: {
                    hosts: claimedIps.slice(0, 20),
                    macs: [macKey],
                    protocols: ['ARP']
                },
                nextPivot: 'Check the switch MAC table and whether proxy ARP is expected.',
                meta: { mac: macKey, addresses: claimedIps.length }
            }));
        }

        findings.sort(function (a, b) { return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.confidence - a.confidence; });
        return findings.slice(0, 8);
    }

    function detectorLateral(packets, scanSources) {
        var bySource = {};
        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var f = fields(p);
            if (lower(p.transport) !== 'tcp') continue;
            if (Number(f['tcp.flags.syn']) !== 1 || Number(f['tcp.flags.ack']) !== 0) continue;
            var dport = Number(p.dstport);
            if (!LATERAL_PORTS[dport]) continue;
            var src = srcHost(p);
            var dst = dstHost(p);
            if (!src || !dst || scanSources[src]) continue;
            var source = bySource[src] || (bySource[src] = {
                src: src, targets: {}, services: {}, ports: {}, events: []
            });
            source.targets[dst] = true;
            source.services[LATERAL_PORTS[dport]] = true;
            source.ports[dport] = true;
            source.events.push({ packet: p, index: i, service: LATERAL_PORTS[dport] });
        }

        var findings = [];
        for (var key in bySource) {
            if (!has(bySource, key)) continue;
            var source = bySource[key];
            var targets = Object.keys(source.targets);
            var services = Object.keys(source.services);
            var ports = Object.keys(source.ports).map(Number);
            if (targets.length < 2) continue;
            if (services.length < 2 && source.events.length < 4) continue;
            var evidence = [];
            for (var e = 0; e < source.events.length && evidence.length < 24; e++) {
                evidence.push(evidenceFor(source.events[e].packet, source.events[e].index,
                    source.events[e].service + ' → ' + dstHost(source.events[e].packet)));
            }
            var portFilter = ports.map(function (port) { return 'tcp.dstport == ' + port; }).join(' || ');
            findings.push(finding({
                detector: 'lateral',
                key: 'lateral|' + source.src,
                title: 'Possible lateral movement from ' + source.src,
                severity: 'medium',
                confidence: Math.min(90, 55 + targets.length * 3 + services.length * 3),
                summary: plural(targets.length, 'internal host') + ' contacted over ' +
                    plural(services.length, 'remote-access service') + ': ' + services.join(', ') + '.',
                detail: 'One source attempted remote-access services on several hosts. Confirm whether this is an administrator or a compromised account.',
                evidence: evidence,
                filter: 'ip.src == ' + quoteHost(source.src, source.src.indexOf(':') >= 0) +
                    ' && (' + portFilter + ')',
                entities: {
                    hosts: [source.src].concat(targets.slice(0, 16)),
                    ports: ports.slice(0, 16),
                    protocols: ['TCP']
                },
                nextPivot: 'Look for successful sessions, then trace the account and source host.',
                meta: { source: source.src, targets: targets.length, services: services }
            }));
        }
        findings.sort(function (a, b) { return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.confidence - a.confidence; });
        return findings.slice(0, 6);
    }

    function detectorRare(packets) {
        if (packets.length < 40) return [];
        var counts = {};
        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var proto = String(p.dec && p.dec.proto || '').toUpperCase();
            if (!proto) continue;
            if (!counts[proto]) counts[proto] = { proto: proto, events: [], firstField: p.fields };
            counts[proto].events.push({ packet: p, index: i });
        }
        var findings = [];
        for (var proto in counts) {
            if (!has(counts, proto) || COMMON_PROTOCOLS[proto]) continue;
            var entry = counts[proto];
            if (entry.events.length > 3) continue;
            var protoNo = Number(entry.firstField && entry.firstField['ip.proto']);
            var filter = isFinite(protoNo) ? 'ip.proto == ' + protoNo : frameFilter(
                entry.events.slice(0, 8).map(function (item) { return item.packet.no; })
            );
            findings.push(finding({
                detector: 'rare',
                key: 'rare|' + proto,
                title: 'Rare protocol: ' + proto,
                severity: 'info',
                confidence: 45,
                summary: plural(entry.events.length, 'packet') + ' used ' + proto + ' in this capture.',
                detail: 'Rare protocols are not automatically malicious, but they deserve a quick check because attackers often use less-monitored protocols.',
                evidence: entry.events.slice(0, 10).map(function (item) {
                    return evidenceFor(item.packet, item.index, proto);
                }),
                filter: filter,
                entities: { protocols: [proto] },
                nextPivot: 'Inspect the packet bytes and confirm the protocol is expected on this network.',
                meta: { protocol: proto }
            }));
        }
        return findings.slice(0, 5);
    }

    function detectorLongLived(packets) {
        var groups = {};
        var firstTime = null;
        var lastTime = null;
        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var t = packetTime(p);
            if (firstTime == null) firstTime = t;
            lastTime = t;
            var shape = conversationShape(p);
            if (!shape) continue;
            var group = groups[shape.key] || (groups[shape.key] = {
                shape: shape, first: t, last: t, packets: 0, firstIndex: i, lastIndex: i,
                firstPacket: p, lastPacket: p, bytes: 0
            });
            group.packets++;
            group.bytes += Number(p.len) || 0;
            if (t < group.first) { group.first = t; group.firstIndex = i; group.firstPacket = p; }
            if (t >= group.last) { group.last = t; group.lastIndex = i; group.lastPacket = p; }
        }
        var span = (lastTime || 0) - (firstTime || 0);
        if (span < 600) return [];
        var findings = [];
        for (var key in groups) {
            if (!has(groups, key)) continue;
            var group = groups[key];
            var duration = group.last - group.first;
            if (duration < 600 || group.packets < 30 || duration < span * 0.6) continue;
            findings.push(finding({
                detector: 'longlived',
                key: 'long|' + key,
                title: 'Long-lived connection: ' + group.shape.a.host + ' ↔ ' + group.shape.b.host,
                severity: 'info',
                confidence: 45,
                summary: fmtSeconds(duration) + ' with ' + plural(group.packets, 'packet') + ' and ' +
                    fmtBytes(group.bytes) + '.',
                detail: 'Long-lived flows can be normal infrastructure or a persistent channel. Compare their cadence and payload with the rest of the capture.',
                evidence: [
                    evidenceFor(group.firstPacket, group.firstIndex, 'first packet'),
                    evidenceFor(group.lastPacket, group.lastIndex, 'last packet')
                ],
                filter: conversationFilter(group.shape),
                entities: {
                    hosts: [group.shape.a.host, group.shape.b.host],
                    ports: unique([group.shape.a.port, group.shape.b.port]).map(Number),
                    protocols: [group.shape.proto.toUpperCase()]
                },
                nextPivot: 'Check for periodic payloads or keepalives inside the flow.',
                meta: { duration: duration, packets: group.packets }
            }));
        }
        findings.sort(function (a, b) { return b.meta.duration - a.meta.duration; });
        return findings.slice(0, 3);
    }

    function summarize(packets, name) {
        var summary = {
            name: name || 'capture',
            packetCount: packets.length,
            bytes: 0,
            first: null,
            last: null,
            hosts: {},
            domains: {},
            macs: {},
            services: {},
            protocols: {}
        };
        var total = 0;
        var seen = {};

        function mark(map, key, packet, index) {
            var value = String(key == null ? '' : key);
            if (!value) return;
            if (!map[value]) {
                map[value] = { count: 0, no: packetNo(packet), index: index, time: packetTime(packet) };
            }
            map[value].count++;
        }

        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var f = fields(p);
            total += Number(p.len) || 0;
            var t = packetTime(p);
            if (summary.first == null || t < summary.first) summary.first = t;
            if (summary.last == null || t > summary.last) summary.last = t;

            var hosts = [f['ip.src'], f['ip.dst'], f['ipv6.src'], f['ipv6.dst'],
                f['arp.src.proto_ipv4'], f['arp.dst.proto_ipv4']];
            for (var h = 0; h < hosts.length; h++) {
                if (isUsefulHost(hosts[h])) mark(summary.hosts, trimName(hosts[h]), p, i);
            }

            var domains = [];
            domains = domains.concat(asArray(f['dns.qry.name']));
            domains = domains.concat(asArray(f['tls.handshake.extensions_server_name']));
            domains = domains.concat(asArray(f['http.host']));
            for (var d = 0; d < domains.length; d++) {
                var domain = trimName(domains[d]);
                if (!domain || isIp(domain) || domain.indexOf(' ') >= 0) continue;
                mark(summary.domains, domain, p, i);
            }

            var macs = [f['eth.src'], f['eth.dst'], f['arp.src.hw_mac'], f['arp.dst.hw_mac']];
            for (var m = 0; m < macs.length; m++) {
                if (isUsefulMac(macs[m])) mark(summary.macs, lower(macs[m]), p, i);
            }

            var proto = lower(p.transport) || lower(p.dec && p.dec.proto);
            var sPort = p.srcport === '' || p.srcport == null ? 0 : Number(p.srcport);
            var dPort = p.dstport === '' || p.dstport == null ? 0 : Number(p.dstport);
            var isTcpUdp = proto === 'tcp' || proto === 'udp';
            if (isTcpUdp && dPort) {
                if (SERVICE_PORTS[dPort] || dPort < 1024) {
                    mark(summary.services, dstHost(p) + ':' + dPort + '/' + proto, p, i);
                }
                if (SERVICE_PORTS[sPort] || sPort < 1024) {
                    mark(summary.services, srcHost(p) + ':' + sPort + '/' + proto, p, i);
                }
            }

            var protoName = String(p.dec && p.dec.proto || '').toUpperCase();
            if (protoName && !seen[protoName]) {
                seen[protoName] = true;
                summary.protocols[protoName] = { count: 0, no: packetNo(p), index: i };
            }
            if (protoName) summary.protocols[protoName].count++;
        }
        summary.bytes = total;
        summary.duration = summary.first != null && summary.last != null ? Math.max(0, summary.last - summary.first) : 0;
        summary.entityCount = Object.keys(summary.hosts).length + Object.keys(summary.domains).length +
            Object.keys(summary.macs).length + Object.keys(summary.services).length;
        return summary;
    }

    function compare(current, baseline, baselineName) {
        if (!current || !baseline) return [];
        var categories = [
            { key: 'domains', label: 'domain', many: 'domains', detectorKey: 'domains', severity: 'medium', maxEvidence: 20 },
            { key: 'hosts', label: 'host', many: 'hosts', detectorKey: 'hosts', severity: 'medium', maxEvidence: 16 },
            { key: 'services', label: 'service endpoint', many: 'service endpoints', detectorKey: 'services', severity: 'low', maxEvidence: 14 },
            { key: 'macs', label: 'MAC address', many: 'MAC addresses', detectorKey: 'macs', severity: 'low', maxEvidence: 10 }
        ];
        var findings = [];
        for (var c = 0; c < categories.length; c++) {
            var category = categories[c];
            var baseMap = baseline[category.key] || {};
            var currMap = current[category.key] || {};
            var novel = Object.keys(currMap).filter(function (key) { return !baseMap[key]; });
            if (!novel.length) continue;
            novel.sort(function (a, b) {
                var ai = currMap[a].index || 0;
                var bi = currMap[b].index || 0;
                return ai - bi || a.localeCompare(b);
            });
            var evidence = [];
            for (var n = 0; n < novel.length && n < category.maxEvidence; n++) {
                var item = currMap[novel[n]];
                var packet = null;
                if (item.index != null) {
                    packet = { no: item.no, dec: { proto: category.label } };
                }
                evidence.push({
                    no: item.no,
                    index: item.index,
                    label: novel[n],
                    time: item.time || 0
                });
            }
            var first = currMap[novel[0]];
            var detailLines = [];
            for (var di = 0; di < Math.min(novel.length, 100); di++) {
                detailLines.push(novel[di] + ' (first #' + currMap[novel[di]].no + ')');
            }
            var entities = {};
            entities[category.detectorKey] = novel.slice(0, 100);
            findings.push(finding({
                detector: 'correlation',
                key: 'new|' + category.key + '|' + baselineName + '|' + current.name,
                title: 'New ' + (novel.length === 1 ? category.label : category.many) + ' after baseline',
                severity: category.severity,
                confidence: 95,
                summary: plural(novel.length, 'new ' + category.label, 'new ' + category.many) + ' first appear after ' +
                    (baselineName || 'the baseline capture') + '. First: ' + novel[0] + ' at frame #' + first.no + '.',
                detail: 'Baseline "' + (baselineName || baseline.name || 'baseline') + '" did not contain these ' +
                    (novel.length === 1 ? category.label : category.many) + '. ' + detailLines.join(', ') + '.',
                evidence: evidence,
                filter: frameFilter(evidence.map(function (item) { return item.no; })),
                entities: entities,
                nextPivot: 'Filter the first-seen frames, then trace the earliest new ' + category.label + ' back to its stream.',
                meta: { category: category.key, baseline: baselineName || baseline.name, count: novel.length, novel: novel },
                comparison: true
            }));
        }
        return findings;
    }

    function analyze(viewer, options) {
        options = options || {};
        var packets = (viewer && viewer.packets) ? viewer.packets : (Array.isArray(viewer) ? viewer : []);
        var started = Date.now();
        var errors = [];
        var all = [];

        function run(name, fn) {
            try {
                var result = fn();
                if (result && result.length) all = all.concat(result);
            } catch (err) {
                errors.push({ detector: name, error: err && err.message ? err.message : String(err) });
            }
        }

        run('beaconing', function () { return detectorBeaconing(packets); });
        var scanFindings = [];
        run('scan', function () { scanFindings = detectorScan(packets); return scanFindings; });
        run('dns', function () { return detectorDns(packets); });
        run('exfiltration', function () { return detectorExfiltration(packets); });
        run('credentials', function () { return detectorCredentials(packets); });
        run('arp', function () { return detectorArp(packets); });
        var scanSources = {};
        for (var s = 0; s < scanFindings.length; s++) {
            if (scanFindings[s].meta && scanFindings[s].meta.source) scanSources[scanFindings[s].meta.source] = true;
        }
        run('lateral', function () { return detectorLateral(packets, scanSources); });
        run('rare', function () { return detectorRare(packets); });
        run('longlived', function () { return detectorLongLived(packets); });

        if (options.baseline) {
            try {
                var currentSummary = options.currentSummary || summarize(packets, viewer && viewer.name);
                var comparison = compare(currentSummary, options.baseline, options.baselineName);
                if (comparison.length) all = all.concat(comparison);
            } catch (err) {
                errors.push({ detector: 'correlation', error: err && err.message ? err.message : String(err) });
            }
        }

        var fakeViewer = viewer && viewer.packets ? viewer : { name: (viewer && viewer.name) || 'capture', packets: packets };
        var seen = {};
        var findings = [];
        for (var f = 0; f < all.length; f++) {
            var item = all[f];
            item.capture = fakeViewer.name || 'capture';
            item.fingerprint = fingerprint(fakeViewer, item);
            item.benign = isBenign(item.fingerprint);
            item.frames = unique((item.evidence || []).map(function (e) { return e.no; })).map(Number);
            if (seen[item.fingerprint]) continue;
            seen[item.fingerprint] = true;
            findings.push(item);
        }
        findings.sort(function (a, b) {
            return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
                b.confidence - a.confidence ||
                String(a.title).localeCompare(String(b.title));
        });

        var stats = {
            total: findings.length,
            active: 0,
            benign: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            durationMs: Date.now() - started,
            detectorErrors: errors,
            capture: fakeViewer.name || 'capture',
            packetCount: packets.length
        };
        for (var c = 0; c < findings.length; c++) {
            if (findings[c].benign) stats.benign++;
            else stats.active++;
            if (findings[c].severity === 'high') stats.high++;
            else if (findings[c].severity === 'medium') stats.medium++;
            else if (findings[c].severity === 'low') stats.low++;
            else stats.info++;
        }
        return {
            findings: findings,
            stats: stats,
            generatedAt: new Date().toISOString(),
            capture: fakeViewer.name || 'capture',
            detectors: Object.keys(DETECTOR_LABELS).map(function (key) {
                return { key: key, label: DETECTOR_LABELS[key] };
            })
        };
    }

    function emptyCase() {
        var now = new Date().toISOString();
        return {
            version: 1,
            id: 'case-' + Date.now().toString(36),
            name: 'Untitled case',
            createdAt: now,
            updatedAt: now,
            notes: '',
            findings: [],
            packetRefs: []
        };
    }

    function normalizeCase(value) {
        var base = emptyCase();
        var data = value && typeof value === 'object' ? value : {};
        base.id = data.id || base.id;
        base.name = data.name || base.name;
        base.createdAt = data.createdAt || base.createdAt;
        base.updatedAt = data.updatedAt || base.updatedAt;
        base.notes = typeof data.notes === 'string' ? data.notes : '';
        base.findings = Array.isArray(data.findings) ? data.findings : [];
        base.packetRefs = Array.isArray(data.packetRefs) ? data.packetRefs : [];
        return base;
    }

    function readCase() {
        return normalizeCase(safeGet(CASE_KEY, null));
    }

    function writeCase(data) {
        data.updatedAt = new Date().toISOString();
        safeSet(CASE_KEY, data);
        return data;
    }

    function pinFinding(item, captureName) {
        var data = readCase();
        var existing = null;
        for (var i = 0; i < data.findings.length; i++) {
            if (data.findings[i].id === item.fingerprint) { existing = data.findings[i]; break; }
        }
        var added = false;
        if (!existing) {
            added = true;
            existing = {
                id: item.fingerprint,
                capture: captureName || item.capture || 'capture',
                detector: item.detector,
                title: item.title,
                severity: item.severity,
                confidence: item.confidence,
                summary: item.summary,
                detail: item.detail,
                frames: (item.frames || []).slice(0, 40),
                filter: item.filter,
                entities: clone(item.entities || {}),
                nextPivot: item.nextPivot,
                evidence: clone((item.evidence || []).slice(0, 40)),
                pinnedAt: new Date().toISOString(),
                note: ''
            };
            data.findings.push(existing);
        }
        var evidence = existing.evidence || [];
        for (var e = 0; e < evidence.length && e < 40; e++) {
            addPacketRefTo(data, existing.capture, evidence[e].no, evidence[e].label || existing.title, existing.id);
        }
        writeCase(data);
        return { added: added, entry: existing, data: data };
    }

    function unpinFinding(id) {
        var data = readCase();
        data.findings = data.findings.filter(function (item) { return item.id !== id; });
        data.packetRefs = data.packetRefs.filter(function (item) { return item.findingId !== id; });
        writeCase(data);
        return data;
    }

    function isPinned(id) {
        var data = readCase();
        for (var i = 0; i < data.findings.length; i++) if (data.findings[i].id === id) return true;
        return false;
    }

    function addPacketRefTo(data, capture, no, label, findingId) {
        var item = {
            capture: capture || 'capture',
            no: Number(no),
            label: label || ('frame #' + no),
            note: '',
            findingId: findingId || '',
            addedAt: new Date().toISOString()
        };
        if (!isFinite(item.no)) return;
        for (var i = 0; i < data.packetRefs.length; i++) {
            var ref = data.packetRefs[i];
            if (ref.capture === item.capture && Number(ref.no) === item.no) return;
        }
        data.packetRefs.push(item);
    }

    function addPacketRef(capture, no, label, findingId) {
        var data = readCase();
        addPacketRefTo(data, capture, no, label, findingId);
        writeCase(data);
        return data;
    }

    function removePacketRef(index) {
        var data = readCase();
        if (index >= 0 && index < data.packetRefs.length) data.packetRefs.splice(index, 1);
        writeCase(data);
        return data;
    }

    function setCaseName(name) {
        var data = readCase();
        data.name = String(name == null ? '' : name).trim() || 'Untitled case';
        return writeCase(data);
    }

    function setCaseNotes(notes) {
        var data = readCase();
        data.notes = String(notes == null ? '' : notes);
        return writeCase(data);
    }

    function clearCase() {
        var data = emptyCase();
        safeSet(CASE_KEY, data);
        return data;
    }

    function caseSummary() {
        var data = readCase();
        var bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
        for (var i = 0; i < data.findings.length; i++) {
            if (bySeverity[data.findings[i].severity] != null) bySeverity[data.findings[i].severity]++;
        }
        return {
            id: data.id,
            name: data.name,
            notes: data.notes,
            updatedAt: data.updatedAt,
            findingCount: data.findings.length,
            packetRefCount: data.packetRefs.length,
            severity: bySeverity
        };
    }

    function exportJson() {
        var data = readCase();
        return JSON.stringify({
            version: data.version,
            id: data.id,
            name: data.name,
            createdAt: data.createdAt,
            updatedAt: data.updatedAt,
            generatedAt: new Date().toISOString(),
            notes: data.notes,
            findings: data.findings,
            packetRefs: data.packetRefs
        }, null, 2);
    }

    function exportMarkdown() {
        var data = readCase();
        var lines = [];
        lines.push('# PCAP Case: ' + (data.name || 'Untitled case'));
        lines.push('');
        lines.push('- Case ID: `' + data.id + '`');
        lines.push('- Created: ' + data.createdAt);
        lines.push('- Updated: ' + data.updatedAt);
        lines.push('- Findings: ' + data.findings.length);
        lines.push('- Packet references: ' + data.packetRefs.length);
        lines.push('');
        lines.push('## Notes');
        lines.push('');
        lines.push(data.notes ? data.notes : '_No case notes._');
        lines.push('');
        lines.push('## Findings');
        lines.push('');
        if (!data.findings.length) {
            lines.push('_No findings pinned._');
        } else {
            for (var i = 0; i < data.findings.length; i++) {
                var f = data.findings[i];
                lines.push('### ' + (i + 1) + '. [' + SEVERITY_LABEL[f.severity] + ' · ' + f.confidence +
                    '%] ' + f.title);
                lines.push('');
                lines.push('- Capture: ' + f.capture);
                lines.push('- Detector: ' + (DETECTOR_LABELS[f.detector] || f.detector));
                if (f.summary) lines.push('- Summary: ' + f.summary);
                if (f.detail) lines.push('- Detail: ' + f.detail);
                lines.push('- Evidence frames: ' + (f.frames && f.frames.length ?
                    f.frames.map(function (no) { return '#' + no; }).join(', ') : 'none'));
                if (f.filter) lines.push('- Display filter: `' + f.filter + '`');
                var entities = entityText(f.entities);
                if (entities) lines.push('- Entities: ' + entities);
                if (f.nextPivot) lines.push('- Next pivot: ' + f.nextPivot);
                if (f.note) lines.push('- Analyst note: ' + f.note);
                lines.push('');
            }
        }
        lines.push('## Packet references');
        lines.push('');
        if (!data.packetRefs.length) {
            lines.push('_No packet references._');
        } else {
            for (var r = 0; r < data.packetRefs.length; r++) {
                var ref = data.packetRefs[r];
                lines.push('- `' + ref.capture + '` frame #' + ref.no + ': ' + (ref.label || 'packet') +
                    (ref.note ? ' · ' + ref.note : ''));
            }
        }
        lines.push('');
        lines.push('_Generated by NETMAP local triage. Detection is deterministic; AI explanations are separate and clearly marked._');
        return lines.join('\n');
    }

    function entityText(entities) {
        if (!entities) return '';
        var parts = [];
        var labels = {
            hosts: 'hosts', domains: 'domains', macs: 'MACs',
            ports: 'ports', protocols: 'protocols', services: 'services'
        };
        for (var key in entities) {
            if (!has(entities, key)) continue;
            var values = asArray(entities[key]).filter(function (value) {
                return value !== '' && value != null;
            });
            if (!values.length) continue;
            parts.push((labels[key] || key) + ': ' + values.slice(0, 24).join(', ') +
                (values.length > 24 ? ' …' : ''));
        }
        return parts.join(' · ');
    }

    function download(kind) {
        var isJson = kind === 'json';
        var text = isJson ? exportJson() : exportMarkdown();
        var data = readCase();
        var safeName = (data.name || 'pcap-case').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'pcap-case';
        var blob = new Blob([text], { type: isJson ? 'application/json' : 'text/markdown' });
        var url = URL.createObjectURL(blob);
        var link = document.createElement('a');
        link.href = url;
        link.download = safeName + (isJson ? '.json' : '.md');
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
        return link.download;
    }

    // ------------------------------------------------------------------
    // Investigation brief, evidence ledger and entity graph
    // ------------------------------------------------------------------

    function safeQuote(value) {
        return String(value == null ? '' : value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    function entityFilter(type, value, extra) {
        var text = String(value == null ? '' : value);
        if (!text) return '';
        if (type === 'host') {
            var field = text.indexOf(':') >= 0 ? 'ipv6.addr' : 'ip.addr';
            return field + ' == "' + safeQuote(text) + '"';
        }
        if (type === 'domain') {
            return '(dns.qry.name == "' + safeQuote(text) +
                '" || tls.handshake.extensions_server_name == "' + safeQuote(text) +
                '" || http.host == "' + safeQuote(text) + '")';
        }
        if (type === 'mac') {
            var mac = text.toLowerCase();
            return '(eth.src == ' + mac + ' || eth.dst == ' + mac +
                ' || arp.src.hw_mac == ' + mac + ' || arp.dst.hw_mac == ' + mac + ')';
        }
        if (type === 'port') {
            var port = Number(text);
            return isFinite(port) && port > 0 ? 'port == ' + port : '';
        }
        if (type === 'protocol') {
            var proto = text.toLowerCase();
            return proto === 'ssl' ? 'tls' : proto;
        }
        if (type === 'service') {
            var host = extra && extra.host ? extra.host : '';
            var servicePort = extra && extra.port ? Number(extra.port) : 0;
            var serviceProto = extra && extra.proto ? String(extra.proto).toLowerCase() : '';
            var parts = [];
            if (host) parts.push(entityFilter('host', host));
            if (servicePort) parts.push('port == ' + servicePort);
            if (serviceProto === 'tcp' || serviceProto === 'udp') parts.push(serviceProto);
            return parts.length ? parts.map(function (part) { return '(' + part + ')'; }).join(' && ') : '';
        }
        return '';
    }

    function entityNodeLabel(type) {
        return type === 'host' ? 'Host' : type === 'domain' ? 'Domain' : type === 'port' ? 'Port'
            : type === 'mac' ? 'MAC' : type === 'service' ? 'Service' : 'Protocol';
    }

    function serviceParts(value) {
        var match = /^(.*):([0-9]+)\/(tcp|udp)$/i.exec(String(value || ''));
        if (!match) return null;
        return { host: match[1], port: Number(match[2]), proto: match[3].toLowerCase() };
    }

    function addGraphNode(nodes, type, value, count, no, extra) {
        if (value == null || value === '') return null;
        var key = type + '|' + String(value);
        var node = nodes[key];
        if (!node) {
            node = nodes[key] = {
                key: key,
                type: type,
                value: String(value),
                label: entityNodeLabel(type),
                filter: entityFilter(type, value, extra),
                count: 0,
                firstNo: no || 0
            };
        }
        node.count += count == null ? 1 : count;
        if (!node.firstNo && no) node.firstNo = no;
        return key;
    }

    function buildEntityGraph(packets, findings, summary, options) {
        options = options || {};
        var maxNodes = options.maxNodes || 5000;
        var nodes = {};
        var edges = {};
        var edgeOrder = [];

        function addEdge(a, b, type) {
            if (!a || !b || a === b) return;
            var key = a < b ? a + '::' + b : b + '::' + a;
            var edge = edges[key];
            if (!edge) {
                edge = edges[key] = { key: key, a: a, b: b, count: 0, type: type || '' };
                edgeOrder.push(key);
            }
            edge.count++;
        }

        for (var i = 0; i < packets.length; i++) {
            var p = packets[i];
            var no = packetNo(p);
            var f = fields(p);
            var aHost = srcHost(p);
            var bHost = dstHost(p);
            var hostAKey = aHost ? addGraphNode(nodes, 'host', aHost, 1, no) : null;
            var hostBKey = bHost ? addGraphNode(nodes, 'host', bHost, 1, no) : null;
            if (hostAKey && hostBKey) addEdge(hostAKey, hostBKey, 'conversation');

            var domainSeen = {};
            var domains = [];
            domains = domains.concat(asArray(f['dns.qry.name']));
            domains = domains.concat(asArray(f['tls.handshake.extensions_server_name']));
            domains = domains.concat(asArray(f['http.host']));
            for (var d = 0; d < domains.length; d++) {
                var domain = trimName(domains[d]);
                if (!domain || isIp(domain) || domain.indexOf(' ') >= 0 || domainSeen[domain]) continue;
                domainSeen[domain] = true;
                var domainKey = addGraphNode(nodes, 'domain', domain, 1, no);
                if (hostAKey) addEdge(hostAKey, domainKey, 'name');
                if (hostBKey) addEdge(hostBKey, domainKey, 'name');
            }

            var proto = lower(p.transport) || lower(p.dec && p.dec.proto);
            var protoKey = proto ? addGraphNode(nodes, 'protocol', proto, 1, no) : null;
            if (hostAKey && protoKey) addEdge(hostAKey, protoKey, 'protocol');
            if (hostBKey && protoKey) addEdge(hostBKey, protoKey, 'protocol');

            var portSeen = {};
            var ports = [p.dstport, p.srcport];
            for (var q = 0; q < ports.length; q++) {
                var port = ports[q] === '' || ports[q] == null ? 0 : Number(ports[q]);
                if (!port || portSeen[port]) continue;
                portSeen[port] = true;
                if (port >= 1024 && !SERVICE_PORTS[port]) continue;
                var portKey = addGraphNode(nodes, 'port', String(port), 1, no);
                var serviceHost = q === 0 ? bHost : aHost;
                var serviceHostKey = q === 0 ? hostBKey : hostAKey;
                if (q === 0 && hostBKey) addEdge(hostBKey, portKey, 'service');
                if (q === 1 && hostAKey) addEdge(hostAKey, portKey, 'service');
                if (serviceHost && (proto === 'tcp' || proto === 'udp')) {
                    var serviceName = serviceHost + ':' + port + '/' + proto;
                    var serviceKey = addGraphNode(nodes, 'service', serviceName, 1, no, {
                        host: serviceHost,
                        port: port,
                        proto: proto
                    });
                    if (serviceHostKey) addEdge(serviceHostKey, serviceKey, 'service');
                }
            }

            var macs = [f['eth.src'], f['eth.dst']];
            for (var m = 0; m < macs.length; m++) {
                if (!isUsefulMac(macs[m])) continue;
                var macKey = addGraphNode(nodes, 'mac', lower(macs[m]), 1, no);
                if (m === 0 && hostAKey) addEdge(hostAKey, macKey, 'link');
                if (m === 1 && hostBKey) addEdge(hostBKey, macKey, 'link');
            }
        }

        var services = summary && summary.services ? summary.services : {};
        for (var serviceName in services) {
            if (!has(services, serviceName)) continue;
            var parts = serviceParts(serviceName);
            if (!parts) continue;
            addGraphNode(nodes, 'service', serviceName, 0, services[serviceName].no, parts);
        }

        for (var fi = 0; fi < findings.length; fi++) {
            var entities = findings[fi].entities || {};
            for (var type in entities) {
                if (!has(entities, type)) continue;
                var values = asArray(entities[type]);
                var nodeType = type === 'hosts' ? 'host' : type === 'domains' ? 'domain'
                    : type === 'macs' ? 'mac' : type === 'ports' ? 'port'
                    : type === 'services' ? 'service' : type === 'protocols' ? 'protocol' : '';
                if (!nodeType) continue;
                for (var vi = 0; vi < values.length; vi++) {
                    var value = nodeType === 'protocol' ? String(values[vi]).toLowerCase() : values[vi];
                    var extra = nodeType === 'service' ? serviceParts(values[vi]) : null;
                    addGraphNode(nodes, nodeType, value, 0, 0, extra || {});
                }
            }
        }

        var nodeList = Object.keys(nodes).map(function (key) { return nodes[key]; })
            .filter(function (node) { return !!node.filter; });
        nodeList.sort(function (a, b) {
            return b.count - a.count || a.type.localeCompare(b.type) || a.value.localeCompare(b.value);
        });
        var kept = {};
        var limited = nodeList.length > maxNodes;
        for (var n = 0; n < nodeList.length && n < maxNodes; n++) kept[nodeList[n].key] = true;

        var edgeList = edgeOrder.map(function (key) { return edges[key]; });
        for (var e = 0; e < edgeList.length; e++) {
            var edge = edgeList[e];
            edge.aNode = nodes[edge.a];
            edge.bNode = nodes[edge.b];
            edge.filter = edge.aNode && edge.bNode && edge.aNode.filter && edge.bNode.filter ?
                '(' + edge.aNode.filter + ') && (' + edge.bNode.filter + ')' : '';
            edge.label = edge.aNode && edge.bNode ?
                edge.aNode.value + ' to ' + edge.bNode.value : '';
        }
        edgeList = edgeList.filter(function (edge) {
            return edge.filter && kept[edge.a] && kept[edge.b];
        }).sort(function (a, b) { return b.count - a.count || a.label.localeCompare(b.label); });

        var keptList = nodeList.filter(function (node) { return kept[node.key]; });
        var typeCounts = {};
        for (var t = 0; t < nodeList.length; t++) {
            typeCounts[nodeList[t].type] = (typeCounts[nodeList[t].type] || 0) + 1;
        }
        return {
            nodes: keptList,
            edges: edgeList,
            totalNodes: nodeList.length,
            totalEdges: edgeOrder.length,
            limited: limited,
            typeCounts: typeCounts
        };
    }

    function buildTimeline(packets, findings, caseData, capture) {
        var byNo = {};
        for (var p = 0; p < packets.length; p++) byNo[Number(packets[p].no)] = packets[p];
        var events = [];

        function addEvent(item) {
            var no = Number(item.no);
            var packet = byNo[no] || null;
            events.push({
                at: packet ? packetTime(packet) : null,
                rel: packet && packet.rel != null ? packet.rel : null,
                no: packet ? no : (isFinite(no) ? no : 0),
                title: item.title || 'Event',
                detail: item.detail || '',
                severity: item.severity || 'info',
                source: item.source || 'finding',
                findingId: item.findingId || '',
                filter: item.filter || '',
                present: !!packet,
                capture: item.capture || capture
            });
        }

        for (var i = 0; i < findings.length; i++) {
            var item = findings[i];
            var frames = item.frames || [];
            addEvent({
                no: frames.length ? frames[0] : 0,
                title: item.title,
                detail: item.summary || item.detail || '',
                severity: item.severity,
                source: item.source === 'case' ? 'case' : 'finding',
                findingId: item.id || item.fingerprint || '',
                filter: item.filter || ''
            });
        }

        var caseFindings = caseData && caseData.findings ? caseData.findings : [];
        for (var c = 0; c < caseFindings.length; c++) {
            var caseItem = caseFindings[c];
            if (caseItem.capture !== capture) continue;
            if (caseItem.id && findings.some(function (active) { return (active.id || active.fingerprint) === caseItem.id; })) continue;
            var caseFrames = caseItem.frames || [];
            addEvent({
                no: caseFrames.length ? caseFrames[0] : 0,
                title: caseItem.title || 'Pinned finding',
                detail: caseItem.summary || caseItem.note || '',
                severity: caseItem.severity || 'info',
                source: 'case',
                findingId: caseItem.id || '',
                filter: caseItem.filter || ''
            });
        }

        var refs = caseData && caseData.packetRefs ? caseData.packetRefs : [];
        for (var r = 0; r < refs.length; r++) {
            var ref = refs[r];
            if (ref.capture !== capture) continue;
            addEvent({
                no: ref.no,
                title: ref.label || ('Packet #' + ref.no),
                detail: ref.note || 'Case packet reference',
                severity: 'info',
                source: 'case-ref',
                filter: 'frame.number == ' + Number(ref.no)
            });
        }

        events.sort(function (a, b) {
            if (a.at == null && b.at == null) return a.no - b.no;
            if (a.at == null) return 1;
            if (b.at == null) return -1;
            return a.at - b.at || a.no - b.no || a.title.localeCompare(b.title);
        });
        return events;
    }

    function buildHypotheses(findings) {
        var active = findings.filter(function (item) { return !item.benign; });
        var hypotheses = [];
        for (var i = 0; i < active.length && hypotheses.length < 5; i++) {
            var item = active[i];
            var frames = item.frames || [];
            hypotheses.push({
                rank: hypotheses.length + 1,
                title: item.title,
                detector: item.detector,
                severity: item.severity,
                confidence: item.confidence,
                frames: frames.slice(0, 24),
                filter: item.filter || '',
                statement: (item.summary || item.detail || item.title) +
                    (frames.length ? ' Evidence starts at frame #' + frames[0] + '.' : ' No frame reference is attached.')
            });
        }
        if (!hypotheses.length) {
            hypotheses.push({
                rank: 1,
                title: 'No local detector fired',
                detector: 'none',
                severity: 'info',
                confidence: 0,
                frames: [],
                filter: '',
                statement: 'No deterministic detector produced an active finding for this capture. ' +
                    'This is not proof that the traffic is benign. Review conversations, rare services and the case notes before closing.'
            });
        }
        return hypotheses;
    }

    function buildRecommendations(findings, stats) {
        var out = [];
        var seen = {};
        function add(text) {
            var value = String(text || '').trim();
            if (!value || seen[value.toLowerCase()]) return;
            seen[value.toLowerCase()] = true;
            out.push(value);
        }
        for (var i = 0; i < findings.length && out.length < 8; i++) {
            if (findings[i].benign) continue;
            add(findings[i].nextPivot);
        }
        if (!out.length) {
            add('Review the busiest conversations and rare services, then record a scope decision in the case file.');
            add('Pin at least one representative packet so the conclusion can be reproduced later.');
        }
        add('Validate every hypothesis against the cited frames. Local detectors are deterministic heuristics and can produce false positives.');
        if (!stats || !stats.active) {
            add('Document the capture timeframe, filters used and the reason the case is being closed.');
        }
        return out.slice(0, 10);
    }

    function brief(viewer, options) {
        options = options || {};
        var packets = (viewer && viewer.packets) ? viewer.packets : (Array.isArray(viewer) ? viewer : []);
        var capture = (viewer && viewer.name) || options.capture || 'capture';
        var analysis = analyze(viewer, options);
        var summary = summarize(packets, capture);
        var caseData = readCase();
        var caseForCapture = (caseData.findings || []).filter(function (item) {
            return item.capture === capture;
        });
        var findings = analysis.findings.slice();
        var activeIds = {};
        for (var i = 0; i < findings.length; i++) activeIds[findings[i].fingerprint] = true;

        var caseOnly = [];
        for (var c = 0; c < caseForCapture.length; c++) {
            var pinned = caseForCapture[c];
            if (activeIds[pinned.id]) continue;
            var copy = clone(pinned);
            copy.source = 'case';
            copy.benign = isBenign(pinned.id);
            if (!copy.frames || !copy.frames.length) copy.frames = (copy.evidence || []).map(function (item) { return item.no; });
            caseOnly.push(copy);
        }

        var ledger = [];
        var all = findings.concat(caseOnly);
        for (var l = 0; l < all.length; l++) {
            var item = all[l];
            if (item.benign) continue;
            var evidence = item.evidence || [];
            var frames = (item.frames || evidence.map(function (e) { return e.no; })).map(Number)
                .filter(function (no, index, list) { return isFinite(no) && list.indexOf(no) === index; });
            var citations = [];
            var missing = [];
            for (var f = 0; f < frames.length; f++) {
                var packet = packets[frames[f] - 1];
                var match = packet && Number(packet.no) === frames[f] ? packet : null;
                var record = evidence.filter(function (e) { return Number(e.no) === frames[f]; })[0];
                if (match) {
                    citations.push({
                        no: frames[f],
                        label: record && record.label ? record.label : (match.dec && match.dec.proto) || 'Packet',
                        time: match.rel != null ? match.rel : record && record.time
                    });
                } else {
                    missing.push(frames[f]);
                }
            }
            ledger.push({
                id: item.fingerprint || item.id || ('finding-' + l),
                source: item.source === 'case' ? 'case' : 'active',
                detector: item.detector || 'unknown',
                detectorLabel: DETECTOR_LABELS[item.detector] || item.detector || 'Detector',
                title: item.title || 'Finding',
                severity: item.severity || 'info',
                confidence: item.confidence == null ? 0 : item.confidence,
                summary: item.summary || '',
                detail: item.detail || '',
                frames: frames,
                citations: citations,
                missingFrames: missing,
                uncited: !frames.length,
                filter: item.filter || '',
                entities: clone(item.entities || {}),
                nextPivot: item.nextPivot || '',
                note: item.note || ''
            });
        }

        var ledgerIds = {};
        for (var id = 0; id < ledger.length; id++) ledgerIds[ledger[id].id] = true;
        var caseOnlyForTimeline = caseOnly.map(function (item) {
            if (ledgerIds[item.id]) return item;
            var copy = clone(item);
            copy.source = 'case';
            return copy;
        });
        var timelineFindings = findings.filter(function (item) { return !item.benign; }).concat(caseOnlyForTimeline);
        var timeline = buildTimeline(packets, timelineFindings, caseData, capture);
        var graph = buildEntityGraph(packets, ledger, summary, { maxNodes: 5000 });
        var hypotheses = buildHypotheses(findings);
        var stats = analysis.stats || {};
        var severity = { high: 0, medium: 0, low: 0, info: 0 };
        for (var s = 0; s < ledger.length; s++) {
            if (severity[ledger[s].severity] != null) severity[ledger[s].severity]++;
        }

        var overview = [];
        overview.push(plural(summary.packetCount, 'packet') + ' from ' + plural(Object.keys(summary.hosts).length, 'host') +
            ' and ' + plural(Object.keys(summary.domains).length, 'domain') + ' over ' +
            fmtSeconds(summary.duration) + '.');
        overview.push(plural(ledger.length, 'active finding') + ': ' + severity.high + ' high, ' +
            severity.medium + ' medium, ' + severity.low + ' low, ' + severity.info + ' info. ' +
            plural(stats.benign || 0, 'finding') + ' marked benign.');
        if (hypotheses.length) {
            overview.push('Top local hypothesis: ' + hypotheses[0].title + ' (' +
                (hypotheses[0].confidence || 0) + '% confidence, ' + hypotheses[0].severity + ').');
        }
        overview.push('Detection is local and deterministic. The AI narrative, when generated, only explains the evidence ledger and never adds findings.');

        var cited = 0;
        var uncited = 0;
        var missingCount = 0;
        for (var ci = 0; ci < ledger.length; ci++) {
            if (ledger[ci].uncited) uncited++;
            else cited++;
            missingCount += ledger[ci].missingFrames.length;
        }

        return {
            version: 1,
            generatedAt: new Date().toISOString(),
            capture: capture,
            stats: {
                packets: summary.packetCount,
                bytes: summary.bytes,
                duration: summary.duration,
                hosts: Object.keys(summary.hosts).length,
                domains: Object.keys(summary.domains).length,
                macs: Object.keys(summary.macs).length,
                services: Object.keys(summary.services).length,
                active: ledger.length,
                benign: stats.benign || 0,
                severity: severity,
                detectorErrors: stats.detectorErrors || []
            },
            summary: summary,
            overview: overview,
            hypotheses: hypotheses,
            ledger: ledger,
            timeline: timeline,
            graph: graph,
            recommendations: buildRecommendations(findings, stats),
            case: {
                name: caseData.name || 'Untitled case',
                notes: caseData.notes || '',
                pinned: caseData.findings.length,
                refs: caseData.packetRefs.length,
                currentCapturePinned: caseForCapture.length
            },
            integrity: {
                claims: ledger.length,
                cited: cited,
                uncited: uncited,
                missingFrames: missingCount,
                detectorErrors: stats.detectorErrors || []
            }
        };
    }

    window.PcapTriage = {
        analyze: analyze,
        summarize: summarize,
        compare: compare,
        brief: brief,
        entityFilter: entityFilter,
        detectorLabels: DETECTOR_LABELS,
        severityOrder: SEVERITY_ORDER,
        severityLabel: SEVERITY_LABEL,
        entityText: entityText,
        isBenign: isBenign,
        setBenign: setBenign,
        clearBenign: clearBenign,
        fingerprint: fingerprint,
        case: {
            read: readCase,
            summary: caseSummary,
            pin: pinFinding,
            unpin: unpinFinding,
            isPinned: isPinned,
            addPacketRef: addPacketRef,
            removePacketRef: removePacketRef,
            setName: setCaseName,
            setNotes: setCaseNotes,
            clear: clearCase,
            exportJson: exportJson,
            exportMarkdown: exportMarkdown,
            download: download
        }
    };
})();
