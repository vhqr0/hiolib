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
        (raise StopIteration))
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

  (async-defn peek-sep [self [sep b"\r\n"]]
    ;; peek bytes contained atleast 1 sep
    (async-wait (.peek-until self (fn [buf] (>= (.find buf sep) 0)))))

  (async-defn read-exactly [self n]
    (let [buf (async-wait (.peek-atleast self n))
          #(buf1 buf2) #((cut buf n) (cut buf n None))]
      (setv self.read-buf buf2)
      buf1))

  (async-defn read-line [self [sep b"\r\n"]]
    (let [buf (async-wait (.peek-sep self sep))
          #(buf1 buf2) (.split buf sep 1)]
      (setv self.read-buf buf2)
      buf1))

  (async-defn read-all [self]
    (.join b"" self)))

(export
  :objects [StreamError StreamEOFError StreamOverflowError StreamReader AsyncStreamReader])
