(function () {
    'use strict';

    var input = document.getElementById('fileInput');
    var dropZone = document.getElementById('dropZone');
    var errorBox = document.getElementById('fileError');
    var chooseBtn = document.getElementById('chooseBtn');
    var chooseBtn2 = document.getElementById('chooseBtn2');
    var topOpenBtn = document.getElementById('topOpenBtn');
    var sampleBtn = document.getElementById('sampleBtn');
    var sampleBtn2 = document.getElementById('sampleBtn2');

    function showError(message) {
        if (!errorBox) return;
        errorBox.textContent = message;
        errorBox.hidden = false;
    }

    function clearError() {
        if (!errorBox) return;
        errorBox.textContent = '';
        errorBox.hidden = true;
    }

    function openCapture(file, name) {
        if (!file) return;
        if (!file.size) {
            showError('That file is empty.');
            return;
        }
        if (typeof window.openPcapFile !== 'function') {
            showError('The packet viewer failed to load. Reload the page and try again.');
            return;
        }
        clearError();
        try {
            window.openPcapFile(file, name || file.name || 'capture');
        } catch (err) {
            showError('Could not open the capture: ' + (err && err.message ? err.message : err));
        }
    }

    window.pcapOpenFileRequest = function () {
        if (!input) return;
        input.value = '';
        input.click();
    };

    if (input) {
        input.addEventListener('change', function () {
            openCapture(input.files && input.files[0]);
        });
    }

    if (chooseBtn) {
        chooseBtn.addEventListener('click', function () { window.pcapOpenFileRequest(); });
    }

    if (chooseBtn2) {
        chooseBtn2.addEventListener('click', function () { window.pcapOpenFileRequest(); });
    }

    if (topOpenBtn) {
        topOpenBtn.addEventListener('click', function () { window.pcapOpenFileRequest(); });
    }

    if (dropZone) {
        dropZone.addEventListener('click', function () { window.pcapOpenFileRequest(); });
        dropZone.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
                e.preventDefault();
                window.pcapOpenFileRequest();
            }
        });
    }

    function hasFiles(e) {
        var types = e.dataTransfer && e.dataTransfer.types;
        if (!types) return false;
        for (var i = 0; i < types.length; i++) {
            if (types[i] === 'Files') return true;
        }
        return false;
    }

    var dragDepth = 0;

    window.addEventListener('dragenter', function (e) {
        if (!hasFiles(e)) return;
        e.preventDefault();
        dragDepth++;
        if (dropZone) dropZone.classList.add('dragover');
    });

    window.addEventListener('dragover', function (e) {
        if (!hasFiles(e)) return;
        e.preventDefault();
        if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
    });

    window.addEventListener('dragleave', function (e) {
        if (!hasFiles(e)) return;
        dragDepth = Math.max(0, dragDepth - 1);
        if (!dragDepth && dropZone) dropZone.classList.remove('dragover');
    });

    window.addEventListener('drop', function (e) {
        if (!hasFiles(e)) return;
        e.preventDefault();
        dragDepth = 0;
        if (dropZone) dropZone.classList.remove('dragover');
        var files = e.dataTransfer.files;
        if (files && files.length) openCapture(files[0]);
    });

    function openSample() {
        var base64 = window.SAMPLE_CAPTURE_BASE64;
        if (!base64) {
            showError('The bundled sample capture is unavailable.');
            return;
        }
        var binary;
        try {
            binary = atob(base64);
        } catch (err) {
            showError('The bundled sample capture could not be decoded.');
            return;
        }
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        var name = window.SAMPLE_CAPTURE_NAME || 'sample.pcap';
        var file;
        try {
            file = new File([bytes], name, { type: 'application/vnd.tcpdump.pcap' });
        } catch (err) {
            file = new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
        }
        openCapture(file, name);
    }

    if (sampleBtn) sampleBtn.addEventListener('click', openSample);
    if (sampleBtn2) sampleBtn2.addEventListener('click', openSample);

    document.addEventListener('keydown', function (e) {
        var ctrl = e.ctrlKey || e.metaKey;
        if (!ctrl || e.altKey || e.shiftKey) return;
        if (e.key !== 'o' && e.key !== 'O') return;
        if (document.querySelector('.pcap-window')) return;
        e.preventDefault();
        window.pcapOpenFileRequest();
    });
})();
