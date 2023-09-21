(require
  hiolib.rule :readers * *)

(import
  asyncio
  socket
  socketserver [ThreadingTCPServer BaseRequestHandler]
  hiolib.stream.stream *)

(async-defclass NullStream [(async-name Stream)]
  (async-defn read1 [self]
    b"")

  (async-defn write1 [self buf]))

(defn start-server [callback host port]
  (defclass Server [ThreadingTCPServer]
    (setv address-family socket.AF-UNSPEC
          allow-reuse-address True))
  (defclass Handler [BaseRequestHandler]
    (setv handle callback))
  (Server #(host port) Handler))

(defclass SocketStream [Stream]
  (defn #-- init [self sock #** kwargs]
    (#super-- init #** kwargs)
    (setv self.sock sock))

  (defn close1 [self]
    (unless self.sock._closed
      (.close self.sock))))

(defclass TCPStream [SocketStream]
  (defn read1 [self]
    (.recv self.sock 4096))

  (defn write1 [self buf]
    (.sendall self.sock buf))

  (defn [classmethod] open-connection [cls host port]
    (let [sock (socket.create-connection #(host port))]
      (cls :sock sock)))

  (defn [classmethod] start-server [cls callback host port]
    (defn _callback [handler]
      (let [sock handler.request]
        (callback (cls :sock sock))))
    (start-server _callback host port)))

(defclass TLSStream [SocketStream]
  (defn #-- init [ssock #** kwargs]
    (#super-- init #** kwargs)
    (setv self.ssock ssock))

  (defn read1 [self]
    (.recv self.ssock 4096))

  (defn write1 [self buf]
    (.sendall self.ssock buf))

  (defn [classmethod] open-connection [cls host port tls-ctx tls-host]
    (let [sock (socket.create-connection #(host port))
          ssock (try
                  (.wrap-socket tls-ctx sock :server-hostname tls-host)
                  (except [Exception]
                    (.close sock)
                    (raise)))]
      (cls :sock sock :ssock ssock)))

  (defn [classmethod] start-server [cls callback host port tls-ctx]
    (defn _callback [handler]
      (let [sock handler.request
            ssock (.wrap-socket tls-ctx sock :server-side True)]
        (callback (cls :sock sock :ssock ssock))))
    (start-server _callback host port)))

(defclass AsyncioStream [AsyncStream]
  (defn #-- init [self reader writer #** kwargs]
    (#super-- init #** kwargs)
    (setv self.reader reader
          self.writer writer))

  (defn/a close1 [self]
    (unless (.is-closing self.writer)
      (.close self.writer)
      (await (.wait-closed self.writer))))

  (defn/a read1 [self]
    (await (.read self.reader 4096)))

  (defn/a write1 [self buf]
    (.write self.writer buf)
    (await (.drain self.writer))))

(defclass AsyncTCPStream [AsyncioStream]
  (defn/a [classmethod] open-connection [cls host port]
    (let [#(reader writer) (await (asyncio.open-connection host port))]
      (cls :reader reader :writer writer)))

  (defn/a [classmethod] start-server [cls callback host port]
    (defn/a _callback [reader writer]
      (await (callback (cls :reader reader :writer writer))))
    (await (asyncio.start-server _callback host port :reuse-address True))))

(defclass AsyncTLSStream [AsyncioStream]
  (defn/a [classmethod] open-connection [cls host port tls-ctx tls-host]
    (let [#(reader writer) (await (asyncio.open-connection host port :ssl tls-ctx :server-hostname tls-host))]
      (cls :reader reader :writer writer)))

  (defn/a [classmethod] start-server [cls callback host port tls-ctx]
    (defn/a _callback [reader writer]
      (await (callback (cls :reader reader :writer writer))))
    (await (asyncio.start-server _callback host port :ssl tls-ctx :reuse-address True))))

(export
  :objects [NullStream AsyncNullStream TCPStream AsyncTCPStream TLSStream AsyncTLSStream])
