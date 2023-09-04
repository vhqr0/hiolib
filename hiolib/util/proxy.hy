;; socks5: https://www.rfc-editor.org/rfc/rfc1928
;; trojan: https://trojan-gfw.github.io/trojan/protocol

(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  enum [IntEnum]
  socket
  hiolib.stream *
  hiolib.struct *
  hiolib.util.ws *)

(async-defclass ProxyConnector [(async-name Connector)]
  (defn #-- init [self host port #* args #** kwargs]
    (#super-- init #* args #** kwargs)
    (setv self.host host
          self.port port)))

(async-defclass ProxyAcceptor [(async-name Acceptor)])

(defn http-build-addr [host port]
  (.format (if (> (.find host ":") 0) "[{}]:{}" "{}:{}")
           host port))

(defn http-parse-addr [addr]
  (if (= (get addr 0) "[")
      (let [idx (.find addr "]")]
        (unless (> idx 0)
          (raise ValueError))
        (if (and (< (+ idx 1) (len addr)) (= (get addr (+ idx 1) ":")))
            #((cut addr 1 idx) (int (cut addr (+ idx 2) None)))
            #((cut addr 1 idx) 80)))
      (let [sp (.split addr ":" 1)]
        (ecase (len sp)
               2 #((get sp 0) (int (get sp 1)))
               1 #((get sp 0) 80)))))

(async-defclass HTTPConnector [(async-name ProxyConnector)]
  (defn get-next-head-pre-head [self]
    (let [addr (http-build-addr self.host self.port)]
      (.pack (async-name HTTPReq) "CONNECT" addr "HTTP/1.1" {"Host" addr})))

  (async-defn connect1 [self next-stream]
    (let [#(_ status _ _)
          (async-wait (.unpack-from-stream (async-name HTTPResp) next-stream))]
      (unless (= status "200")
        (raise StructValidationError))
      next-stream)))

(async-defclass HTTPAcceptor [(async-name ProxyAcceptor)]
  (async-defn accept1 [self next-stream]
    (let [#(meth path ver headers)
          (async-wait (.unpack-from-stream (async-name HTTPReq) next-stream))
          #(host port) (http-parse-addr (get headers "Host"))]
      (setv self.host host
            self.port port)
      (if (= meth "CONNECT")
          (async-wait (.write next-stream (.pack (async-name HTTPResp) ver "200" "OK" {"Connection" "close"})))
          (let [headers (dfor #(k v) (.items headers) :if (not (.startswith k "Proxy-")) k v)]
            (+= next-stream.read-buf (.pack (async-name HTTPReq) meth path ver headers))))
      next-stream)))

(defclass Socks5Atype [IntEnum]
  (setv DN 3 V4 1 V6 4))

(defstruct Socks5V4Host
  [[bytes host
    :len 4
    :from (socket.inet-pton socket.AF-INET it)
    :to (socket.inet-ntop socket.AF-INET it)]])

(defstruct Socks5V6Host
  [[bytes host
    :len 16
    :from (socket.inet-pton socket.AF-INET6 it)
    :to (socket.inet-ntop socket.AF-INET6 it)]])

(defstruct Socks5DNHost
  [[varlen host
    :len 1
    :from (.encode it)
    :to (.decode it)]])

(defstruct Socks5Addr
  [[int atype :len 1]
   [struct [host]
    :struct (ecase atype
                   Socks5Atype.DN (async-name Socks5DNHost)
                   Socks5Atype.V4 (async-name Socks5V4Host)
                   Socks5Atype.V6 (async-name Socks5V6Host))]
   [int port :len 2]])

(defstruct Socks5AuthReq
  [[int ver :len 1 :to-validate (= it 5)]
   [varlen meths :len 1 :to-validate (in 0 it)]])

(defstruct Socks5AuthRep
  [[int ver :len 1 :to-validate (= it 5)]
   [int meth :len 1 :to-validate (= it 0)]])

(defstruct Socks5Req
  [[int ver :len 1 :to-validate (= it 5)]
   [int cmd :len 1 :to-validate (= it 1)]
   [int rsv :len 1 :to-validate (= it 0)]
   [struct [atype host port] :struct (async-name Socks5Addr)]])

(defstruct Socks5Rep
  [[int ver :len 1 :to-validate (= it 5)]
   [int rep :len 1 :to-validate (= it 0)]
   [int rsv :len 1 :to-validate (= it 0)]
   [struct [atype host port] :struct (async-name Socks5Addr)]])

(defstruct TrojanReq
  [[line auth :sep b"\r\n"]
   [int cmd :len 1 :to-validate (= it 1)]
   [struct [atype host port] :struct (async-name Socks5Addr)]
   [line empty :sep b"\r\n" :to-validate (not it)]])

(async-defclass Socks5Connector [(async-name ProxyConnector)]
  (defn get-next-head-pre-head [self]
    (+ (.pack (async-name Socks5AuthReq) 5 b"\x00")
       (.pack (async-name Socks5Req) 5 1 0 Socks5Atype.DN self.host self.port)))

  (async-defn connect1 [self next-stream]
    (async-wait (.unpack-from-stream (async-name Socks5AuthRep) next-stream))
    (async-wait (.unpack-from-stream (async-name Socks5Rep) next-stream))
    next-stream))

(async-defclass Socks5Acceptor [(async-name ProxyAcceptor)]
  (async-defn accept1 [self next-stream]
    (async-wait (.unpack-from-stream (async-name Socks5AuthReq) next-stream))
    (async-wait (.write next-stream
                        (+ (.pack (async-name Socks5AuthRep) 5 0)
                           (.pack (async-name Socks5Rep) 5 0 0 Socks5Atype.V4 "0.0.0.0" 0))))
    (let [#(_ _ _ _ host port)
          (async-wait (.unpack-from-stream (async-name Socks5Req) next-stream))]
      (setv self.host host
            self.port port))
    next-stream))

(defclass TrojanMixin []
  (defn #-- init [self auth #* args #** kwargs]
    (#super-- init #* args #** kwargs)
    (setv self.auth auth)))

(async-defclass TrojanConnector [TrojanMixin (async-name ProxyConnector)]
  (defn get-next-head-pre-head [self]
    (.pack (async-name TrojanReq) self.auth 1 Socks5Atype.DN self.host self.port "")))

(async-defclass TrojanAcceptor [TrojanMixin (async-name ProxyAcceptor)]
  (async-defn accept1 [self next-stream]
    (let [#(auth _ _ host port _)
          (async-wait (.unpack-from-stream (async-name TrojanReq) next-stream))]
      (unless (= auth self.auth)
        (raise StructValidationError))
      (setv self.host host
            self.port port)
      next-stream)))

(async-defclass AutoAcceptor [(async-name ProxyAcceptor)]
  (async-defn accept1 [self next-stream]
    (let [buf (async-wait (.peek next-stream))]
      (let [acceptor (if (= (get buf 0) 5) ((async-name Socks5Acceptor)) ((async-name HTTPAcceptor)))
            stream (async-wait (.accept1 acceptor next-stream))]
        (setv self.host acceptor.host
              self.port acceptor.port)
        stream))))

(export
  :objects [ProxyConnector AsyncProxyConnector ProxyAcceptor AsyncProxyAcceptor
            HTTPConnector AsyncHTTPConnector HTTPAcceptor AsyncHTTPAcceptor
            Socks5Connector AsyncSocks5Connector Socks5Acceptor AsyncSocks5Acceptor
            TrojanConnector AsyncTrojanConnector TrojanAcceptor AsyncTrojanAcceptor
            AutoAcceptor AsyncAutoAcceptor])
