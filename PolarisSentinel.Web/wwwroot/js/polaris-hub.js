(function () {
    let connection = null;
    let retryTimer = null;
    let starting = null;
    let stopping = false;

    function retry() {
        if (stopping || retryTimer !== null) return;
        retryTimer = setTimeout(function () {
            retryTimer = null;
            start();
        }, 3000);
    }

    function build() {
        if (connection) {
            return connection;
        }

        connection = new signalR.HubConnectionBuilder()
            .withUrl('/trafficHub')

            .withAutomaticReconnect([0, 2000, 5000, 10000, 30000])
            .configureLogging(signalR.LogLevel.Warning)
            .build();

        connection.onreconnecting(function (error) {
            console.warn('SignalR reconnecting', error);
        });
        connection.onreconnected(function () {
            console.info('SignalR reconnected');
        });
        connection.onclose(function (error) {
            console.warn('SignalR closed', error);
            retry();
        });

        return connection;
    }

    async function start() {
        const hub = build();
        if (!stopping && !starting && hub.state === signalR.HubConnectionState.Disconnected) {
            starting = hub.start().catch(function (err) {
                console.error('SignalR start failed', err);
                retry();
            }).finally(function () { starting = null; });
        }
        if (starting) await starting;
        return hub;
    }

    function on(event, handler) {
        build().on(event, handler);
    }

    window.addEventListener('beforeunload', function () {
        stopping = true;
        clearTimeout(retryTimer);
        if (connection && connection.state !== signalR.HubConnectionState.Disconnected) {
            connection.stop();
        }
    });

    window.polarisHub = { start: start, on: on };
})();
