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

let direct_tcpv4
    ?(clock=default_monotonic_clock)
    ?(random=default_random)
    ?(time=default_time) ip =
  impl (tcpv4_direct_conf ()) $ random $ clock $ time $ ip

let tcpv6_direct_conf () = object
  inherit base_configurable
  method ty = random @-> mclock @-> time @-> ipv6 @-> (tcp: 'a tcp typ)
  method name = "tcp"
  method module_name = "Utcp_mirage.Make_v6"
  method! connect _ modname = function
    | [_random; _mclock; _time; ip] -> Fmt.str "Lwt.return (%s.connect %s)" modname ip
    | _ -> failwith "direct tcpv6"
end

let direct_tcpv6
    ?(clock=default_monotonic_clock)
    ?(random=default_random)
    ?(time=default_time) ip =
  impl (tcpv6_direct_conf ()) $ random $ clock $ time $ ip

let tcpv4v6_direct_conf () = object
  inherit base_configurable
  method ty = random @-> mclock @-> time @-> ipv4v6 @-> (tcp: 'a tcp typ)
  method name = "tcp"
  method module_name = "Utcp_mirage.Make_v4v6"
  method! connect _ modname = function
    | [_random; _mclock; _time; ip] -> Fmt.str "Lwt.return (%s.connect %s)" modname ip
    | _ -> failwith "direct tcpv4v6"
end

let direct_tcpv4v6
    ?(clock=default_monotonic_clock)
    ?(random=default_random)
    ?(time=default_time) ip =
  impl (tcpv4v6_direct_conf ()) $ random $ clock $ time $ ip

let main =
  foreign ~keys:[Key.abstract port]
    ~packages:[ package ~sublibs:["mirage"] "utcp"]
    "Unikernel.Main" (stackv4v6 @-> job)

let stack =
  let e = etif default_network in
  let a = arp e in
  let i4 = create_ipv4 e a in
  let i6 = create_ipv6 default_network e in
  let i4i6 = create_ipv4v6 i4 i6 in
  let tcp = direct_tcpv4v6 i4i6 in
  let ipv4_only = Key.ipv4_only ()
  and ipv6_only = Key.ipv6_only ()
  in
  direct_stackv4v6 ~tcp ~ipv4_only ~ipv6_only default_network e a i4 i6

let () =
  register "network" [
    main $ stack
  ]
