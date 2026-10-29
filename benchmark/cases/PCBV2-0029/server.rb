# Tiny WEBrick app for PatchClosure-Bench webrick-crlf-2017-17742-2019-16254.
# Reflects a request query param straight into a RESPONSE HEADER value.
# WEBrick's WEBrick::HTTPResponse#send_header runs check_header(value) on each
# header value at write time; the version-specific CR/LF regex in check_header
# decides whether a control-char-bearing value is written or triggers a 500.
#   V0 (ruby 2.5.0): no check_header             -> \r\n and lone \r / \n all pass
#   V1 (ruby 2.5.1): check_header =~ /\r\n/      -> \r\n blocked; lone \r / \n PASS (residual)
#   V2 (ruby 2.5.8): check_header /[\r\n]/       -> any \r or \n blocked
# The query param is %XX-decoded by WEBrick (HTTPUtils.unescape), so an encoded
# %0d%0a / %0a / %0d in the URL becomes a real CR/LF in the header value.
require "webrick"

server = WEBrick::HTTPServer.new(Port: 8080, BindAddress: "0.0.0.0", Logger: WEBrick::Log.new(File::NULL), AccessLog: [])

server.mount_proc "/" do |req, res|
  x = req.query["x"] || ""
  res["X-Reflected"] = x           # user-controlled value copied into a response header
  res.body = "ok"
  res["Content-Type"] = "text/plain"
end

trap("INT")  { server.shutdown }
trap("TERM") { server.shutdown }
server.start
