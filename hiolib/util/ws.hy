;; https://www.rfc-editor.org/rfc/rfc6455

(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  enum [IntEnum]
  collections [deque]
  random [randbytes]
  base64 [b64encode]
  hashlib [sha1]
  hiolib.stream *
  hiolib.struct *)

(defn http-headers-pack [headers]
  (doto (lfor #(k v) (headers.items) (.format "{}: {}" k v))
        (.append "")))

(defn http-headers-unpack [headers]
  (.pop headers)
  (dfor header headers
        :setv #(k v) (.split header ":" 1)
        (.strip k) (.strip v)))

(defstruct HTTPFirstLine
  [[line firstline
    :sep b"\r\n"
    :from (.join " " it)
    :to (.split it :maxsplit 2)]])

(defstruct HTTPHeaders
  [[line headers
    :sep b"\r\n"
    :repeat-until (not it)
    :from (http-headers-pack it)
    :to (http-headers-unpack it)]])

(defstruct HTTPReq
  [[struct [[meth path ver]] :struct (async-name HTTPFirstLine)]
   [struct [headers] :struct (async-name HTTPHeaders)]])

(defstruct HTTPResp
  [[struct [[ver status reason]] :struct (async-name HTTPFirstLine)]
   [struct [headers] :struct (async-name HTTPHeaders)]])

(defclass WSOp [IntEnum]
  (setv Cont  0x00
        Text  0x01
        Bin   0x02
        Close 0x10
        Ping  0x11
        Pong  0x12))

(defn ws-mask-pload [pload mask]
  (let [arr (bytearray pload)]
    (for [i (range (len arr))]
      (^= (get arr i) (get mask (% i 4))))
    (bytes arr)))

(async-defclass WSFramePloadHead [(async-name Struct)]
  (setv names #("plen" "mask"))

  (defn [staticmethod] pack [plen mask]
    (let [mask-bit (int (bool mask))]
      (+ (cond (< plen 126)
               (bits-pack #(7 0) #(mask-bit plen) 1)
               (< plen 65536)
               (+ (bits-pack #(7 0) #(mask-bit 126) 1)
                  (int-pack plen 2))
               True
               (+ (bits-pack #(7 0) #(mask-bit 127) 1)
                  (int-pack plen 8)))
         mask)))

  (async-defn [staticmethod] unpack-from-stream [reader]
    (let [#(mask-bit plen) (bits-unpack
                             #(7 0) #(1 0x7f)
                             (async-wait (.read-exactly reader 1)))
          plen (cond (= plen 126)
                     (int-unpack (async-wait (.read-exactly reader 2)))
                     (= plen 127)
                     (int-unpack (async-wait (.read-exactly reader 8)))
                     True
                     plen)
          mask (if mask-bit
                   (async-wait (.read-exactly reader 4))
                   b"")]
      #(plen mask))))

(defstruct WSFrame
  [[bits [fin op] :lens [1 7]]
   [struct [plen mask] :struct (async-name WSFramePloadHead)]
   [bytes pload
    :len plen
    :from (if mask (ws-mask-pload it mask) it)
    :to (if mask (ws-mask-pload it mask) it)]])

(async-defclass WSStream [(async-name Stream)]
  (defn #-- init [self [do-mask True] #* args #** kwargs]
    (#super-- init #* args #** kwargs)
    (setv self.do-mask do-mask
          self.pings (deque)
          self.pong None))

  (async-defn read-frame [self]
    (let [#(fin op _ _ pload)
          (async-wait (.unpack-from-stream (async-name WSFrame) self.next-layer))]
      (while (not fin)
        (let [#(next-fin next-op _ _ next-pload)
              (async-wait (.unpack-from-stream (async-name WSFrame) self.next-layer))]
          (unless (= op next-op)
            (raise RuntimeError))
          (setv fin next-fin)
          (+= pload next-pload)
          (when (> (len pload) self.read-buf-size)
            (raise StreamOverflowError))))
      #(op pload)))

  (async-defn write-frame [self op pload]
    (async-wait (.write self.next-layer (.pack (async-name WSFrame)
                                               :fin True
                                               :op op
                                               :plen (len pload)
                                               :mask (if self.do-mask (randbytes 4) b"")
                                               :pload pload))))

  (async-defn read1 [self]
    (while True
      (let [#(op pload) (async-wait (.read-frame self))]
        (ecase op
               WSOp.Cont  None
               WSOp.Text  (return pload)
               WSOp.Bin   (return pload)
               WSOp.Close (return b"")
               WSOp.Ping  (.append self.pings pload)
               WSOp.Pong  (setv self.pong pload)))))

  (async-defn write1 [self buf]
    (while self.pings
      (let [ping (.popleft self.pings)]
        (async-wait (.write-frame self WSOp.Pong ping))))
    (async-wait (.write-frame self WSOp.Bin buf))))

(async-defclass WSConnector [(async-name Connector)]
  (defn #-- init [self host path #* args #** kwargs]
    (#super-- init #* args #** kwargs)
    (setv self.host host
          self.path path))

  (defn get-next-head-pre-head [self]
    (.pack (async-name HTTPReq)
           "GET" self.path "HTTP/1.1"
           {"Host" self.host
            "Upgrade" "websocket"
            "Connection" "Upgrade"
            "Sec-WebSocket-Key" (.decode (b64encode (randbytes 16)))
            "Sec-WebSocket-Version" "13"}))

  (defn get-next-head-pre-frame [self head]
    (.pack (async-name WSFrame)
           :fin True
           :op WSOp.Bin
           :plen (len head)
           :mask (randbytes 4)
           :pload head))

  (async-defn connect1 [self next-stream]
    (let [#(ver status reason headers)
          (async-wait (.unpack-from-stream (async-name HTTPResp) next-stream))]
      (unless (= status "101")
        (raise StructValidationError))
      ((async-name WSStream) :do-mask True :next-layer next-stream))))

(async-defclass WSAcceptor [(async-name Acceptor)]
  (setv magic "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

  (async-defn accept1 [self next-stream]
    (let [#(meth path ver headers)
          (async-wait (.unpack-from-stream (async-name HTTPReq) next-stream))
          host (get headers "Host")
          key (get headers "Sec-WebSocket-Key")
          accept (.decode (b64encode (.digest (sha1 (.encode (+ key self.magic))))))]
      (async-wait (.write next-stream (.pack (async-name HTTPResp)
                                             "HTTP/1.1" "101" "Switching Protocols"
                                             {"Upgrade" "websocket"
                                              "Connection" "Upgrade"
                                              "Sec-WebSocket-Accept" accept})))
      (setv self.host host
            self.path path)
      ((async-name WSStream) :do-mask False :next-layer next-stream))))

(export
  :objects [HTTPReq AsyncHTTPReq HTTPResp AsyncHTTPResp
            WSConnector AsyncWSConnector WSAcceptor AsyncWSAcceptor])
