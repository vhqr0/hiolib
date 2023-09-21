(require
  hiolib.rule :readers * *)

(import
  hiolib.stream.reader *)

(async-defclass StreamWriter []
  (async-defn write1 [self buf]
    (raise NotImplementedError))

  (async-defn write [self buf]
    (when buf
      (async-wait (.write1 self buf)))))

(defclass LayerMixin []
  (defn #-- init [self [next-layer None] #** kwargs]
    (#super-- init #** kwargs)
    (setv self.next-layer next-layer))

  (defn [property] lowest-layer [self]
    (if self.next-layer self.next-layer.lowest-layer self)))

(async-defclass Stream [LayerMixin (async-name StreamWriter) (async-name StreamReader)]
  (async-defn close1 [self])

  (async-defn close [self]
    (try
      (async-wait (.close1 self.lowest-layer))
      (except [Exception])))

  (async-if
    (async-defn #-- aenter [self #* args #** kwargs] self)
    (async-defn #-- enter  [self #* args #** kwargs] self))

  (async-if
    (async-defn #-- aexit [self #* args #** kwargs] (async-wait (.close self)) False)
    (async-defn #-- exit  [self #* args #** kwargs] (async-wait (.close self)) False)))

(async-defclass Connector [LayerMixin]
  (defn get-next-head-pre-head [self]
    b"")

  (defn get-next-head-pre-frame [self head]
    head)

  (defn get-next-head [self head]
    (let [next-head (.get-next-head-pre-head self)]
      (when head
        (+= next-head (.get-next-head-pre-frame self head)))
      next-head))

  (defn get-lowest-head [self head]
    (let [next-head (.get-next-head self head)]
      (if self.next-layer
          (.get-lowest-head self.next-layer next-head)
          next-head)))

  (async-defn connect1 [self next-stream]
    next-stream)

  (async-defn connect [self lowest-stream]
    (let [next-stream (if self.next-layer
                          (async-wait (.connect self.next-layer lowest-stream))
                          lowest-stream)]
      (async-wait (.connect1 self next-stream))))

  (async-defn connect-with-head [self lowest-stream [head b""]]
    (let [lowest-head (.get-lowest-head self head)]
      (async-wait (.write lowest-stream lowest-head)))
    (async-wait (.connect self lowest-stream))))

(async-defclass Acceptor [LayerMixin]
  (async-defn accept1 [self next-stream]
    next-stream)

  (async-defn accept [self lowest-stream]
    (let [next-stream (if self.next-layer
                          (async-wait (.accept self.next-layer lowest-stream))
                          lowest-stream)]
      (async-wait (.accept1 self next-stream)))))

(export
  :objects [Stream AsyncStream Connector AsyncConnector Acceptor AsyncAcceptor])
