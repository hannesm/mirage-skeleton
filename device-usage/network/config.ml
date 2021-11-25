open Mirage

let port =
  let doc = Key.Arg.info ~doc:"The TCP port on which to listen for incoming connections." ["port"] in
  Key.(create "port" Arg.(opt int 8080 doc))

let tcpv4_direct_conf () = object
  inherit base_configurable
  method ty = random @-> mclock @-> time @-> ipv4 @-> (tcp: 'a tcp typ)
  method name = "tcp"
  method module_name = "Utcp_mirage.Make_v4"
  method! connect _ modname = function
    | [_random; _mclock; _time; ip] -> Fmt.str "Lwt.return (%s.connect %s)" modname ip
    | _ -> failwith "direct tcpv4"
end

let direct_tcp
    ?(clock=default_monotonic_clock)
    ?(random=default_random)
    ?(time=default_time) ip =
  impl (tcpv4_direct_conf ()) $ random $ clock $ time $ ip

let main =
  foreign ~keys:[Key.abstract port]
    ~packages:[ package ~sublibs:["mirage"] "utcp"]
    "Unikernel.Main" (stackv4 @-> job)

let stack =
  let e = etif default_network in
  let a = arp e in
  let i = create_ipv4 e a in
  let tcp = direct_tcp i in
  direct_stackv4 ~tcp default_network e a i

let () =
  register "network" [
    main $ stack
  ]
