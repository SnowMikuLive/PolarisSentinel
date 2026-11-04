const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

test('SignalR retries repeated startup failures and exhausted reconnects until recovery', async () => {
    const timers = new Map();
    let nextTimer = 0, attempts = 0, available = false, closed, unloading;
    const hub = {
        state: 'Disconnected',
        onreconnecting() {}, onreconnected() {}, on() {},
        onclose(callback) { closed = callback; },
        async start() { attempts++; if (!available) throw new Error('offline'); this.state = 'Connected'; },
        stop() { this.state = 'Disconnected'; closed(); }
    };
    class Builder {
        withUrl() { return this; }
        withAutomaticReconnect() { return this; }
        configureLogging() { return this; }
        build() { return hub; }
    }
    const window = { addEventListener(name, fn) { if (name === 'beforeunload') unloading = fn; } };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../PolarisSentinel.Web/wwwroot/js/polaris-hub.js'), 'utf8'), {
        window, signalR: { HubConnectionBuilder: Builder, HubConnectionState: { Disconnected: 'Disconnected' }, LogLevel: {} },
        console: { warn() {}, info() {}, error() {} },
        setTimeout(fn) { const id = ++nextTimer; timers.set(id, fn); return id; },
        clearTimeout(id) { timers.delete(id); }
    });
    await window.polarisHub.start();
    for (let i = 0; i < 4; i++) {
        assert.equal(timers.size, 1);
        const [id, fn] = timers.entries().next().value;
        timers.delete(id); fn();
        await new Promise(resolve => setImmediate(resolve));
    }
    assert.equal(attempts, 5);
    available = true;
    await window.polarisHub.start();
    assert.equal(hub.state, 'Connected');
    hub.state = 'Disconnected'; closed();
    const [id, fn] = timers.entries().next().value;
    timers.delete(id); fn();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(hub.state, 'Connected');
    unloading();
    assert.equal(timers.size, 0);
});

function capturePage(initial, selectionResult) {
    const elements = new Map();
    for (const id of ['deviceSelect', 'deviceStatus', 'captureState', 'captureIndicator', 'setDevice', 'refreshDevices', 'requestVerificationToken']) {
        const element = { textContent: '', className: '', value: '', disabled: false, options: [],
            appendChild(option) { this.options.push(option); },
            addEventListener(name, fn) { this[name] = fn; } };
        Object.defineProperty(element, 'innerHTML', { set() { this.options = []; } });
        elements.set(id, element);
    }
    const source = fs.readFileSync(path.join(__dirname, '../PolarisSentinel.Web/Views/TrafficMonitor/Index.cshtml'), 'utf8');
    vm.runInNewContext(source.slice(source.indexOf('const deviceSelect='), source.lastIndexOf('</script>')), {
        document: { getElementById(id) { return elements.get(id); }, createElement() { return {}; } },
        fetch: async (url) => url.endsWith('/select')
            ? { ok: false, json: async () => selectionResult }
            : { ok: true, json: async () => initial },
        console: { error() {} }, setInterval() {}
    });
    return elements;
}

test('capture page restores server-selected adapter and keeps failed-switch error', async () => {
    const elements = capturePage({ current: 'A', npcapDetected: true, devices: [
        { deviceName: 'A', displayName: 'A', isCurrent: true }, { deviceName: 'B', displayName: 'B' }
    ] }, { current: 'A', error: 'Cannot start B' });
    await new Promise(resolve => setImmediate(resolve));
    elements.get('deviceSelect').value = 'B';
    elements.get('setDevice').click();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(elements.get('deviceSelect').value, 'A');
    assert.equal(elements.get('deviceStatus').textContent, 'Cannot start B');
    assert.equal(elements.get('captureState').textContent, 'Capturing');
});

test('capture page reports stopped when no capture is running', async () => {
    const elements = capturePage({ current: null, npcapDetected: true, devices: [] });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(elements.get('captureState').textContent, 'Stopped');
});
