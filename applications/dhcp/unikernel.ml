open Mirage_types_lwt
open Lwt.Infix

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

module Main (C: CONSOLE) (N: NETWORK) (PClock : Mirage_types.PCLOCK) (MClock : Mirage_types.MCLOCK) (Time: TIME) (R: RANDOM) = struct
  module E = Ethernet.Make(N)
  module A = Arp.Make(E)(Time)
  module I = Static_ipv4.Make(E)(A)
  module U = Udp.Make(I)(R)
  module DC = Dhcp_config

  let log c s =
    Astring.String.cuts ~sep:"\n" s |>
    Lwt_list.iter_s (fun line -> C.log c line)

  let of_interest dest net =
    Macaddr.compare dest (N.mac net) = 0 || not (Macaddr.is_unicast dest)

  let dns_header id = { Dns_packet.id ; query = true ; operation = Dns_enum.Update ;
                        authoritative = false ; truncation = false ; recursion_desired = false ;
                        recursion_available = false ; authentic_data = false ; checking_disabled = false ;
                        rcode = Dns_enum.NoError }

  let input_dhcp console clock net u key pclock config leases buf =
    match Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) with
    | Error e ->
      log console (red "Can't parse packet: %s" e) >>= fun () ->
      Lwt.return leases
    | Ok pkt ->
      let now = MClock.elapsed_ns clock |> Duration.to_sec |> Int32.of_int in
      match Dhcp_server.Input.input_pkt config leases pkt now with
      | Dhcp_server.Input.Silence -> Lwt.return leases
      | Dhcp_server.Input.Update leases ->
        log console (blue "Received packet %s - updated lease database" (Dhcp_wire.pkt_to_string pkt)) >>= fun () ->
        Lwt.return leases
      | Dhcp_server.Input.Warning w ->
        log console (yellow "%s" w) >>= fun () ->
        Lwt.return leases
      | Dhcp_server.Input.Error e ->
        log console (red "%s" e) >>= fun () ->
        Lwt.return leases
      | Dhcp_server.Input.Reply (reply, leases, binding) ->
        log console (blue "Received packet %s" (Dhcp_wire.pkt_to_string pkt)) >>= fun () ->
        N.write net ~size:(N.mtu net + Ethernet_wire.sizeof_ethernet) (Dhcp_wire.pkt_into_buf reply) >>= fun _ ->
        log console (blue "Sent reply packet %s" (Dhcp_wire.pkt_to_string reply)) >>= fun () ->
        (match binding, key with
         | None, _ | None, _ -> Lwt.return_unit
         | Some (ip, name), Some (dst, kname, key) ->
           (* TODO ensure that name is a good one *)
           let zone = Dns_name.of_string_exn Dhcp_config.domain in
           match Dns_name.prepend zone name with
           | Error (`Msg msg) ->
             Logs.warn (fun m -> m "couldn't create hostname %s.%a: %s" name Dns_name.pp zone msg) ;
             Lwt.return_unit
           | Ok name ->
             let original_id = 0xDEAD in
             let a =
               let zone = { Dns_packet.q_name = zone ; q_type = Dns_enum.SOA }
               and update = [
                 Dns_packet.Remove (name, Dns_enum.A) ;
                 Dns_packet.Add ({ Dns_packet.name ; ttl = 3600l ; rdata = Dns_packet.A ip })
               ]
               in
               { Dns_packet.zone ; prereq = [] ; update ; addition = [] }
             and header = dns_header original_id
             in
             let ptr =
               (* IP is 1.2.3.4 ; zone is 3.2.1.in-addr.arpa ; hostname 4.3.2.1.in-addr.arpa *)
               let rev = List.rev (List.tl (List.rev (Ipaddr.V4.to_domain_name ip))) in
               Logs.debug (fun m -> m "domain name %a" Fmt.(list ~sep:(unit ".") string) rev) ;
               let hname = Dns_name.of_strings_exn rev in
               let zname =
                 let arr = Dns_name.to_array hname in
                 Dns_name.(of_array (Array.sub arr 0 (Array.length arr - 1)))
               in
               Logs.debug (fun m -> m "hname %a zname %a" Dns_name.pp hname
                              Dns_name.pp zname) ;
               let zone = { Dns_packet.q_name = zname ; q_type = Dns_enum.SOA }
               and update = [
                 Dns_packet.Remove (hname, Dns_enum.PTR) ;
                 Dns_packet.Add ({ Dns_packet.name = hname ; ttl = 3600l ; rdata = Dns_packet.PTR name })
               ]
               in
               { Dns_packet.zone ; prereq = [] ; update ; addition = [] }
             in
             let now = Ptime.v (PClock.now_d_ps pclock) in
             Lwt_list.iter_s (fun update ->
                 match Dns_tsig.encode_and_sign ~proto:`Udp (header, `Update update) now key kname with
                 | Error msg ->
                   Logs.warn (fun m -> m "while encoding and signing nsupdate: %s" msg) ;
                   Lwt.return_unit
                 | Ok (data, _) ->
                   U.write ~dst ~dst_port:53 u data >|= function
                   | Error e -> Logs.warn (fun m -> m "failed to send nsupdate %a" U.pp_error e)
                   | Ok () -> ())
                 [a ; ptr]) >>= fun () ->
        Lwt.return leases

  let start c net pclock clock _time _random _nocrypto =
    (* find potential nsupdate information (ip, key) *)
    let key = match Astring.String.cut ~sep:":" (Key_gen.key ()) with
      | None -> Logs.err (fun m -> m "couldn't parse %s" (Key_gen.key ())) ; None
      | Some (ip, key) -> match Astring.String.cut ~sep:":" key with
        | None -> Logs.err (fun m -> m "couldn't parse name in %s" key) ; None
        | Some (name, key) ->
          match Ipaddr.V4.of_string ip, Dns_name.of_string ~hostname:false name, Dns_packet.dnskey_of_string key with
          | None, _, _ | _, Error _, _ | _, _, None -> Logs.err (fun m -> m "failed to parse key %s" key) ; None
          | Some ip, Ok name, Some dnskey -> Some (ip, name, dnskey)
    in

    (* Get an ARP stack *)
    E.connect net >>= fun e ->
    A.connect e >>= fun a ->
    A.add_ip a DC.ip_address >>= fun () ->
    I.connect ~ip:DC.ip_address ~network:DC.network e a >>= fun i ->
    U.connect i >>= fun u ->

    (* Build a dhcp server *)
    let config = Dhcp_server.Config.make
        ~hostname:DC.hostname
        ~default_lease_time:DC.default_lease_time
        ~max_lease_time:DC.max_lease_time
        ~hosts:DC.hosts
        ~addr_tuple:(DC.ip_address, N.mac net)
        ~network:DC.network
        ~range:DC.range
        ~options:DC.options
    in
    let leases = ref (Dhcp_server.Lease.make_db ()) in
    let listener = N.listen net ~header_size:Ethernet_wire.sizeof_ethernet (fun buf ->
        match Ethernet_packet.Unmarshal.of_cstruct buf with
        | Result.Error s ->
          log c (red "Can't parse packet: %s" s)
        | Result.Ok (ethif_header, ethif_payload) ->
          if of_interest ethif_header.Ethernet_packet.destination net &&
             Dhcp_wire.is_dhcp buf (Cstruct.len buf) then begin
            input_dhcp c clock net u key pclock config !leases buf >>= fun new_leases ->
            leases := new_leases;
            Lwt.return_unit
          end else if ethif_header.Ethernet_packet.ethertype = `ARP then
            A.input a ethif_payload
          else Lwt.return_unit
      ) in
    listener
end
