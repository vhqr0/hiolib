(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *
  hpacket.inet.ipv4 *           ; ipv4-pad-opts
  )

(defpacket [(IPProto.register IPProto.TCP)] TCP [DispOptsMixin CksumProxySelfMixin]
  [[int [src dst] :len 2 :repeat 2]
   [int [seq ack] :len 4 :repeat 2]
   [bits [dataofs res C E U A P R S F] :lens [4 4 1 1 1 1 1 1 1 1]]
   [int win :len 2]
   [int cksum :len 2]
   [int uptr :len 2]
   [bytes opts
    :len (* (- dataofs 5) 4)
    :from (ipv4-pad-opts (TCPOptListStruct.pack it))
    :to (get (TCPOptListStruct.unpack it) 0)]]
  [[src 0] [dst 0] [seq 0] [ack 0] [dataofs 0]
   [res 0] [C 0] [E 0] [U 0] [A 0] [P 0] [R 0] [S 0] [F 0]
   [win 8192] [cksum 0] [uptr 0] [opts #()]]

  (setv disp-whitelist
        #("src" "dst" #("seq") #("ack")
                #("C") #("E") #("U") #("A") #("P") #("R") #("S") #("F")
                "win" #("uptr"))
        cksum-proto IPProto.TCP
        cksum-offset 16)

  (defn post-build [self]
    (#super post-build)
    (when (= self.dataofs 0)
      (setv self.dataofs (// (len self.head) 4)
            self.head (int-replace self.head 12 1 (+ (<< self.dataofs 4) self.res))))))

(define-opt-dict TCPOpt
  [EOL    0
   NOP    1
   MSS    2
   WS     3
   SAckOK 4
   SAck   5
   TS     8]
  [[int type :len 1 :to (normalize it TCPOpt)]
   [varlen data
    :len (if (in type #(0 1)) 0 1)
    :len-from (if (in type #(0 1)) 0 (+ it 2))
    :len-to (if (in type #(0 1)) 0 (- it 2))
    :from (TCPOpt.pack type it)
    :to (TCPOpt.unpack type it)]])

(define-int-opt TCPOpt MSS 2)
(define-int-opt TCPOpt WS  1)

(define-atom-struct-opt TCPOpt SAck
  [int edges :len 4 :repeat-while (async-wait (.peek reader))])

(define-struct-opt TCPOpt TS
  [[int [tsval tsecr] :len 4 :repeat 2]])
