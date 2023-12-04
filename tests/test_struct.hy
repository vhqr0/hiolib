(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  unittest [TestCase]
  random [getrandbits randbytes]
  asyncio
  hiolib.rule *
  hiolib.struct *)

(defstruct TSAll
  [[all a]])

(defstruct TSBytes
  [[bytes b :len 3]])

(defstruct TSInt
  [[int i :len 2]
   [int j :len 2 :order "little"]])

(defstruct TSVarLen
  [[varlen v :len 2]])

(defstruct TSLine
  [[line l :sep b"\r\n"]])

(defstruct TSBits
  [[bits [b1 b2] :lens [3 5]]])

(defstruct TSStruct
  [[struct [line] :struct (async-name TSLine)]
   [struct [i j] :struct (async-name TSInt)]])

(defclass TestStruct [TestCase]
  (defn test-int-pack [self]
    (.assertEqual self (int-unpack b"") 0)
    (.assertEqual self (int-pack 0x1234 2) b"\x12\x34")
    (.assertEqual self (int-unpack b"\x12\x34") 0x1234)
    (.assertEqual self (int-pack 0x1234 2 :order "little") b"\x34\x12")
    (.assertEqual self (int-unpack b"\x34\x12" :order "little") 0x1234)
    (do-n 10
          (let [n (getrandbits 4)
                i (getrandbits (<< n 3))
                b (randbytes n)]
            (.assertEqual self (int-unpack (int-pack i n)) i)
            (.assertEqual self (int-pack (int-unpack b) n) b))))

  (defn test-bits-pack [self]
    (.assertEqual self (bits-pack #(5 0) #(0b101 0b11011) 1) (int-pack 0b10111011 1))
    (.assertEqual self (bits-unpack #(5 0) #(0b111 0b11111) (int-pack 0b10111011 1)) [0b101 0b11011]))

  (defn test-struct-all [self]
    (.assertEqual self (.pack-to-bytes TSAll b"foo") b"foo")
    (.assertEqual self (.unpack-from-bytes TSAll b"foo") #(b"foo"))
    (asyncio.run
      ((fn/a []
         (.assertEqual self (await (.pack-to-bytes AsyncTSAll b"foo")) b"foo")
         (.assertEqual self (await (.unpack-from-bytes AsyncTSAll b"foo")) #(b"foo"))))))

  (defn test-struct-bytes [self]
    (.assertEqual self (.pack-to-bytes TSBytes b"foo") b"foo")
    (.assertEqual self (.unpack-from-bytes TSBytes b"foo") #(b"foo"))
    (with [_ (.assertRaises self StructValidationError)]
      (.unpack-from-bytes TSBytes b"foobar"))
    (asyncio.run
      ((fn/a []
         (.assertEqual self (await (.pack-to-bytes AsyncTSBytes b"foo")) b"foo")
         (.assertEqual self (await (.unpack-from-bytes AsyncTSBytes b"foo")) #(b"foo"))))))

  (defn test-struct-int [self]
    (.assertEqual self (.pack-to-bytes TSInt 0x1234 0x3412) b"\x12\x34\x12\x34")
    (.assertEqual self (.unpack-from-bytes TSInt b"\x12\x34\x12\x34") #(0x1234 0x3412))
    (asyncio.run
      ((fn/a []
         (.assertEqual self (await (.pack-to-bytes AsyncTSInt 0x1234 0x3412)) b"\x12\x34\x12\x34")
         (.assertEqual self (await (.unpack-from-bytes AsyncTSInt b"\x12\x34\x12\x34")) #(0x1234 0x3412))))))

  (defn test-struct-varlen [self]
    (.assertEqual self (.pack-to-bytes TSVarLen b"foo") b"\x00\x03foo")
    (.assertEqual self (.unpack-from-bytes TSVarLen b"\x00\x03foo") #(b"foo"))
    (asyncio.run
      ((fn/a []
         (.assertEqual self (await (.pack-to-bytes AsyncTSVarLen b"foo")) b"\x00\x03foo")
         (.assertEqual self (await (.unpack-from-bytes AsyncTSVarLen b"\x00\x03foo")) #(b"foo"))))))

  (defn test-struct-line [self]
    (.assertEqual self (.pack-to-bytes TSLine "foo") b"foo\r\n")
    (.assertEqual self (.unpack-from-bytes TSLine b"foo\r\n") #("foo"))
    (asyncio.run
      ((fn/a []
         (.assertEqual self (await (.pack-to-bytes AsyncTSLine "foo")) b"foo\r\n")
         (.assertEqual self (await (.unpack-from-bytes AsyncTSLine b"foo\r\n")) #("foo"))))))

  (defn test-struct-bits [self]
    (.assertEqual self (.pack-to-bytes TSBits 0b101 0b11011) (int-pack 0b10111011 1))
    (.assertEqual self (.unpack-from-bytes TSBits (int-pack 0b10111011 1)) #(0b101 0b11011))
    (asyncio.run
      ((fn/a []
         (.assertEqual self (await (.pack-to-bytes AsyncTSBits 0b101 0b11011)) (int-pack 0b10111011 1))
         (.assertEqual self (await (.unpack-from-bytes AsyncTSBits (int-pack 0b10111011 1))) #(0b101 0b11011))))))

  (defn test-struct-struct [self]
    (.assertEqual self (.pack-to-bytes TSStruct "foo" 0x1234 0x3412) b"foo\r\n\x12\x34\x12\x34")
    (.assertEqual self (.unpack-from-bytes TSStruct b"foo\r\n\x12\x34\x12\x34") #("foo" 0x1234 0x3412))
    (asyncio.run
      ((fn/a []
         (.assertEqual self (await (.pack-to-bytes AsyncTSStruct "foo" 0x1234 0x3412)) b"foo\r\n\x12\x34\x12\x34")
         (.assertEqual self (await (.unpack-from-bytes AsyncTSStruct b"foo\r\n\x12\x34\x12\x34")) #("foo" 0x1234 0x3412)))))))

(export
  :objects [TestStruct])
