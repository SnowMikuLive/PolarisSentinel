// Shared SignalR client helper.
//
// Centralises the connection lifecycle so every page gets the same behaviour:
//  - automatic reconnect with a backoff
//  - a single connection per page (no leaked connections on navigation)
//  - the connection is stopped when the page is unloaded
(function () {
    let connection = null;

    function build() {
        if (connection) {
            return connection;
        }

        connection = new signalR.HubConnectionBuilder()
            .withUrl('/trafficHub')
            // Retry with a short backoff; the default schedule is 0/2/10/30s.
            .withAutomaticReconnect([0, 2000, 5000, 10000, 30000])
            .configureLogging(signalR.LogLevel.Warning)
            .build();

        // A dropped connection must not leave the page silently stale.
        connection.onreconnecting(function (error) {
            console.warn('SignalR reconnecting', error);
        });
        connection.onreconnected(function () {
            console.info('SignalR reconnected');
        });
        connection.onclose(function (error) {
            console.warn('SignalR closed', error);
        });

        return connection;
    }

    // Starts the shared connection once; safe to call from several handlers.
    async function start() {
        const hub = build();
        if (hub.state === signalR.HubConnectionState.Disconnected) {
            try {
                await hub.start();
            } catch (err) {
                console.error('SignalR start failed', err);
                // Retry once shortly, which covers a transient server restart.
                setTimeout(function () {
                    if (hub.state === signalR.HubConnectionState.Disconnected) {
                        hub.start().catch(function (e) { console.error('SignalR retry failed', e); });
                    }
                }, 3000);
            }
        }
        return hub;
    }

    // Registers a handler on the shared connection.
    function on(event, handler) {
        build().on(event, handler);
    }

    // Stops the connection when the page goes away.
    window.addEventListener('beforeunload', function () {
        if (connection && connection.state !== signalR.HubConnectionState.Disconnected) {
            connection.stop();
        }
    });

    window.polarisHub = { start: start, on: on };
})();
