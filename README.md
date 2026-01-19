hellas-cli
==========

quickstart
==========

install:

  $ cargo install --git https://github.com/hellas-ai/node

execute:
  $ cargo run -- execute run -p hey

end-to-end
==========

install server features:

  $ cargo install --git https://github.com/hellas-ai/node --features serve

run server:

  $ hellas-cli serve --discovery
  Node Address: bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550
  RPC server running. Press Ctrl+C to stop
  
run client:

  $ cargo run -- execute run -p hey bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550
  Hello! How can I help you today?<|im_end|>%
