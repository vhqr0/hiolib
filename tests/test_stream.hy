(require
  hiolib.rule :readers * *)

(import
  unittest [TestCase]
  random [randbytes getrandbits]
  hiolib.stream *)

(defclass TestStream [TestCase]

  (defn test-reader-read [self]
    (let [stream (BIOStream b"12345\r\n54321\r\n12345")]
      (.assertEqual self (.read-line stream b"\r\n") b"12345")
      (.assertEqual self (.read-exactly stream 3) b"543")
      (.assertEqual self (.read-atmost stream 4) b"21\r\n")
      (.assertEqual self (.read-all stream) b"12345")
      (.assertEqual self (.read stream) b"")))

  (defn test-reader-iter [self]
    (let [buf (randbytes (* 1024 1024))
          stream (BIOStream buf)
          bufs (list stream)]
      (.assertEqual self buf (.join b"" bufs))))

  (defn test-write [self]
    (let [bufs (list-n 10 (randbytes (getrandbits 8)))
          stream (BIOStream)]
      (for [buf bufs]
        (.write stream buf))
      (.assertEqual self (.join b"" bufs) (.getvalue stream)))))
