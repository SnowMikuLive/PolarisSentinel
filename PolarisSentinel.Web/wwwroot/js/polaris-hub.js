(function () {
    let connection = null;

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
        });

        return connection;
    }

    async function start() {
        const hub = build();
        if (hub.state === signalR.HubConnectionState.Disconnected) {
            try {
                await hub.start();
            } catch (err) {
                console.error('SignalR start failed', err);

                setTimeout(function () {
                    if (hub.state === signalR.HubConnectionState.Disconnected) {
                        hub.start().catch(function (e) { console.error('SignalR retry failed', e); });
                    }
                }, 3000);
            }
        }
        return hub;
    }

    function on(event, handler) {
        build().on(event, handler);
    }

    window.addEventListener('beforeunload', function () {
        if (connection && connection.state !== signalR.HubConnectionState.Disconnected) {
            connection.stop();
        }
    });

    window.polarisHub = { start: start, on: on };
})();
