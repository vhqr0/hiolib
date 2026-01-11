(require
  hiolib.rule :readers * *)

(import
  unittest [TestCase]
  random [randbytes getrandbits]
  socket
  scapy.all :as sp
  hpacket.inet :as hi)

(defclass TestTCP [TestCase]
  (defn test-build [self]
    (let [src  (getrandbits 16)
          dst  (getrandbits 16)
          seq  (getrandbits 32)
          ack  (getrandbits 32)
          win  (getrandbits 16)
          uptr (getrandbits 16)]
      (setv hipkt (/ (hi.IPv4)
                     (hi.TCP :src src :dst dst :S 1 :A 1 :E 1 :seq seq :ack ack :win win :uptr uptr
                             :opts [#(hi.TCPOpt.MSS 1460) #(hi.TCPOpt.WS 8) #(hi.TCPOpt.EOL b"")])))
      (setv sppkt (sp.IP (bytes hipkt)))
      (setv tcp (get sppkt 1))
      (.assertIsInstance self tcp sp.TCP)
      (.assertEqual self tcp.sport src)
      (.assertEqual self tcp.dport dst)
      (.assertEqual self tcp.seq seq)
      (.assertEqual self tcp.ack ack)
      (.assertEqual self tcp.window win)
      (.assertEqual self tcp.urgptr uptr)
      (.assertTrue self tcp.flags.S)
      (.assertTrue self tcp.flags.A)
      (.assertTrue self tcp.flags.E)
      (.assertFalse self tcp.flags.F)
      (.assertEqual self (get tcp.options 0) #("MSS" 1460))
      (.assertEqual self (get tcp.options 1) #("WScale" 8))
      (.assertEqual self (get tcp.options 2) #("EOL" None))))

  (defn test-parse [self]
    (let [src  (getrandbits 16)
          dst  (getrandbits 16)
          seq  (getrandbits 32)
          ack  (getrandbits 32)
          win  (getrandbits 16)
          uptr (getrandbits 16)]
      (setv sppkt (/ (sp.IP)
                     (sp.TCP :sport src :dport dst :flags ["S" "A" "E"] :seq seq :ack ack :window win :urgptr uptr
                             :options [#("MSS" 1460) #("WScale" 8) #("EOL" None)])))
      (setv hipkt (hi.IPv4.parse (bytes sppkt)))
      (setv tcp (get hipkt 1))
      (.assertIsInstance self tcp hi.TCP)
      (.assertEqual self tcp.src src)
      (.assertEqual self tcp.dst dst)
      (.assertEqual self tcp.seq seq)
      (.assertEqual self tcp.ack ack)
      (.assertEqual self tcp.win win)
      (.assertEqual self tcp.uptr uptr)
      (.assertTrue self tcp.S)
      (.assertTrue self tcp.A)
      (.assertTrue self tcp.E)
      (.assertFalse self tcp.F)
      (.assertEqual self (get tcp.opts 0) #(hi.TCPOpt.MSS 1460))
      (.assertEqual self (get tcp.opts 1) #(hi.TCPOpt.WS 8))
      (.assertEqual self (get tcp.opts 2) #(hi.TCPOpt.EOL b"")))))

(export
  :objects [TestTCP])
