(require
  hiolib.rule :readers * *)

(import
  hiolib.rule *
  hpacket.packet
  hpacket.packet [IndentPrinter]
  hpacket.inet *
  hpacket.pcap *)

(defmain []
  (let [args (parse-args [["-d" "--debug" :action "store_true" :default False]
                          ["-v" "--verbose" :action "store_true" :default False]
                          ["input"]])]
    (when args.debug
      (setv hpacket.packet.debug True))
    (with [f (open args.input "rb")]
      (let [reader (Pcap.reader f)
            printer (IndentPrinter :char " " :indent 1 :step 2)]
        (for [packet reader]
          (if args.verbose
              (do
                (print "---")
                (.print packet printer)
                (print "---"))
              (.print printer packet)))))))
