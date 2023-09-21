(require
  hiolib.rule :readers * *)

(import io [BytesIO])

(defclass StreamError [Exception])

(defclass StreamEOFError [StreamError])

(defclass StreamOverflowError [StreamError])

(defn bytes-split-at [b n]
  #((cut b n) (cut b n None)))

(async-defclass StreamReader []
  (setv read-buf-size (do-mac (<< 1 16)))

  (defn #-- init [self [buf b""]]
    (setv self.read-buf buf
          self.read-eof False))

  (async-defn read1 []
    (raise NotImplementedError))

  (async-defn peek [self]
    (unless (or self.read-eof self.read-buf)
      (setv self.read-buf (async-wait (.read1 self)))
      (unless self.read-buf
        (setv self.read-eof True)))
    self.read-buf)

  (async-defn peek-until [self predicate]
    (while (not (predicate self.read-buf))
      (let [buf (async-wait (.read1 self))]
        (unless buf
          (setv self.read-eof True)
          (raise StreamEOFError))
        (+= self.read-buf buf)
        (when (> (len self.read-buf) self.read-buf-size)
          (raise StreamOverflowError))))
    self.read-buf)

  (async-defn read [self]
    (let [buf (async-wait (.peek self))]
      (setv self.read-buf b"")
      buf))

  (async-defn read-exactly [self n]
    (async-wait (.peek-until self (fn [buf] (>= (len buf) n))))
    (let [#(buf1 buf2) (bytes-split-at self.read-buf n)]
      (setv self.read-buf buf2)
      buf1))

  (async-defn read-line [self [sep b"\r\n"]]
    (async-wait (.peek-until self (fn [buf] (>= (.find buf sep) 0))))
    (let [#(buf1 buf2) (.split self.read-buf sep 1)]
      (setv self.read-buf buf2)
      buf1)))

(async-defclass BIOStreamReader [(async-name StreamReader)]
  (defn #-- init [self [bio b""] #** kwargs]
    (#super-- init #** kwargs)
    (setv self.bio (BytesIO bio)))

  (async-defn read1 [self]
    (.read self.bio 4096)))

(export
  :objects [StreamError StreamEOFError StreamOverflowError
            StreamReader AsyncStreamReader BIOStreamReader AsyncBIOStreamReader])
