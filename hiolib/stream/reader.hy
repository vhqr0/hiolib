(require
  hiolib.rule :readers * *)

(defclass StreamError [Exception])

(defclass StreamEOFError [StreamError])

(defclass StreamOverflowError [StreamError])

(async-defclass StreamReader []
  (setv read-buf-size (do-mac (<< 1 16)))

  (defn #-- init [self [buf b""]]
    (setv self.read-buf buf
          self.read-eof False))

  (async-defn read1 []
    (raise NotImplementedError))

  (async-defn read [self]
    (let [buf (async-wait (.peek self))]
      (setv self.read-buf b"")
      buf))

  (async-defn next [self]
    (let [buf (async-wait (.read self))]
      (unless buf
        (raise (async-if StopAsyncIteration StopIteration)))
      buf))

  (async-if
    (defn #-- aiter [self #* args #** kwargs] self)
    (defn #-- iter  [self #* args #** kwargs] self))

  (async-if
    (async-defn #-- anext [self #* args #** kwargs] (async-wait (.next self)))
    (async-defn #-- next  [self #* args #** kwargs] (async-wait (.next self))))

  (async-defn peek [self]
    ;; peek non-empty bytes unless eof
    (unless (or self.read-eof self.read-buf)
      (setv self.read-buf (async-wait (.read1 self)))
      (unless self.read-buf
        (setv self.read-eof True)))
    self.read-buf)

  (async-defn peek-more [self]
    ;; strictly extend buf and then peek
    (when self.read-eof
      (raise StreamEOFError))
    (let [buf (async-wait (.read1 self))]
      (unless buf
        (setv self.read-eof True)
        (raise StreamEOFError))
      (+= self.read-buf buf))
    (when (> (len self.read-buf) self.read-buf-size)
      (raise StreamOverflowError))
    self.read-buf)

  (async-defn peek-until [self pred]
    ;; peek bytes satisfied pred
    (let [buf (async-wait (.peek self))]
      (while (not (pred buf))
        (setv buf (async-wait (.peek-more self))))
      buf))

  (async-defn peek-atleast [self n]
    ;; peek atleast n bytes
    (async-wait (.peek-until self (fn [buf] (>= (len buf) n)))))

  (async-defn peek-line [self [sep b"\r\n"]]
    ;; peek next line strip sep and rest bytes
    (let [sp (.split (async-wait (.peek self)) sep 1)]
      (while (<= (len sp) 1)
        (setv sp (.split (async-wait (.peek-more self)) sep 1)))
      sp))

  (async-defn read-atmost [self n]
    (let [buf (async-wait (.peek self))
          #(buf1 buf2) (if (> (len buf) n) #((cut buf n) (cut buf n None)) #(buf b""))]
      (setv self.read-buf buf2)
      buf1))

  (async-defn read-atleast [self n]
    (let [buf (async-wait (.peek-atleast self n))]
      (setv self.read-buf b"")
      buf))

  (async-defn read-exactly [self n]
    (let [buf (async-wait (.peek-atleast self n))
          #(buf1 buf2) #((cut buf n) (cut buf n None))]
      (setv self.read-buf buf2)
      buf1))

  (async-defn read-line [self [sep b"\r\n"]]
    (let [#(buf1 buf2) (async-wait (.peek-line self sep))]
      (setv self.read-buf buf2)
      buf1))

  (async-defn read-all [self]
    (let [bufs (list)]
      (async-for [buf self] (.append bufs buf))
      (.join b"" bufs))))

(export
  :objects [StreamError StreamEOFError StreamOverflowError StreamReader AsyncStreamReader])
