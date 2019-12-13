open Mirage

let main =
  foreign "Unikernel.Main"
    ~packages:[package "fmt"; package "monitoring-experiments"]
    ~deps:[abstract app_info]
    (console @-> job)

let () =
  register "console" [main $ default_console]
