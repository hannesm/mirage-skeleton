open Lwt.Infix

module H (S : Mirage_stack_lwt.V4) (L : Logs.LOG) = struct
  let listen s port =
    S.listen_tcpv4 s ~port (fun flow ->
        let dst, dst_port = S.TCPV4.dst flow in
        L.info (fun f -> f "new tcp connection from IP %s on port %d"
                     (Ipaddr.V4.to_string dst) dst_port);
        S.TCPV4.read flow >>= function
        | Ok `Eof -> L.info (fun f -> f "Closing connection!"); Lwt.return_unit
        | Error e -> L.warn (fun f -> f "Error reading data from established connection: %a" S.TCPV4.pp_error e); Lwt.return_unit
        | Ok (`Data b) ->
          L.info (fun f -> f "read: %d bytes:@.%s" (Cstruct.len b) (Cstruct.to_string b));
          S.TCPV4.close flow
      );
    S.listen s
end

let src = Logs.Src.create "service" ~doc:"Service logging"
module SLog = (val Logs.src_log src : Logs.LOG)

let src = Logs.Src.create "management" ~doc:"Management logging"
module MLog = (val Logs.src_log src : Logs.LOG)

module Main (S: Mirage_stack_lwt.V4) (M : Mirage_stack_lwt.V4) = struct

  module Management = H(M)(MLog)
  module Service = H(S)(SLog)

  let start s m =
    let port = Key_gen.port () in
    Lwt.join [ Service.listen s port ; Management.listen m port ]
end
