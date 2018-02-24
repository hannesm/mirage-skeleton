open Lwt.Infix

let log = Logs.Src.create "speaking clock" ~doc:"At the third stroke..."
module Log = (val Logs.src_log log : Logs.LOG)

module Main (Time: Mirage_types_lwt.TIME) (PClock: Mirage_types.PCLOCK) (MClock: Mirage_types.MCLOCK) = struct

  module Logs_reporter = Mirage_logs.Make(PClock)

  let start _time pclock mclock =
    Logs.(set_level (Some Info));
    Logs_reporter.(create pclock |> run) @@ fun () ->
    let rec speak pclock mclock old_ns () =
      let current_time = PClock.now_d_ps pclock |> Ptime.v in
      let ns = MClock.elapsed_ns mclock in
      Log.info (fun f -> f "ptime %a %Lu ns elapsed since boot, %Lu ns since last output"
                   (Ptime.pp_human ()) current_time ns (Int64.sub ns old_ns)) ;
      OS.Time.sleep_ns 1_000_000L >>= fun () ->
      speak pclock mclock ns ()
    in
    speak pclock mclock (MClock.elapsed_ns mclock) ()

end
