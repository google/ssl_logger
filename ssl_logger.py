# Copyright 2017 Google Inc. All Rights Reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Decrypts and logs a process's SSL traffic.

Hooks the functions SSL_read() and SSL_write() in a given process and logs the
decrypted data to the console and/or to a pcap file.

  Typical usage example:

  ssl_log("wget", "log.pcap", True)

Dependencies:
  frida (https://www.frida.re/):
    sudo pip install frida
  hexdump (https://bitbucket.org/techtonik/hexdump/) if using verbose output:
    sudo pip install hexdump
"""

__author__ = "geffner@google.com (Jason Geffner)"
__version__ = "1.0"


import argparse
import os
import platform
import pprint
import random
import signal
import socket
import struct
import time

import frida

try:
  import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
  pass


_FRIDA_SCRIPT = """
  /**
   * Initializes 'addresses' dictionary and NativeFunctions.
   */
  function initializeGlobals()
  {
    addresses = {};

    var resolver = new ApiResolver("module");

    var exps = [
      ["*libssl*",
        ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session",
        "SSL_SESSION_get_id"]],
      [Process.platform == "darwin" ? "*libsystem*" : "*libc*",
        ["getpeername", "getsockname", "ntohs", "ntohl"]]
      ];
    for (var i = 0; i < exps.length; i++)
    {
      var lib = exps[i][0];
      var names = exps[i][1];

      for (var j = 0; j < names.length; j++)
      {
        var name = names[j];
        var matches = resolver.enumerateMatchesSync("exports:" + lib + "!" +
          name);
        if (matches.length == 0)
        {
          throw "Could not find " + lib + "!" + name;
        }
        else if (matches.length != 1)
        {
          // Sometimes Frida returns duplicates.
          var address = 0;
          var s = "";
          var duplicates_only = true;
          for (var k = 0; k < matches.length; k++)
          {
            if (s.length != 0)
            {
              s += ", ";
            }
            s += matches[k].name + "@" + matches[k].address;
            if (address == 0)
            {
              address = matches[k].address;
            }
            else if (!address.equals(matches[k].address))
            {
              duplicates_only = false;
            }
          }
          if (!duplicates_only)
          {
            throw "More than one match found for " + lib + "!" + name + ": " +
              s;
          }
        }
        addresses[name] = matches[0].address;
      }
    }

    SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int",
      ["pointer"]);
    SSL_get_session = new NativeFunction(addresses["SSL_get_session"],
      "pointer", ["pointer"]);
    SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"],
      "pointer", ["pointer", "pointer"]);
    getpeername = new NativeFunction(addresses["getpeername"], "int", ["int",
      "pointer", "pointer"]);
    getsockname = new NativeFunction(addresses["getsockname"], "int", ["int",
      "pointer", "pointer"]);
    ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"]);
    ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"]);
  }
  initializeGlobals();

  /**
   * Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
   * "dst_port".
   * @param {int} sockfd The file descriptor of the socket to inspect.
   * @param {boolean} isRead If true, the context is an SSL_read call. If
   *     false, the context is an SSL_write call.
   * @return {dict} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
   *     and "dst_port".
   */
  function getPortsAndAddresses(sockfd, isRead)
  {
    var message = {};

    var addrlen = Memory.alloc(4);
    var addr = Memory.alloc(16);

    var src_dst = ["src", "dst"];
    for (var i = 0; i < src_dst.length; i++)
    {
      Memory.writeU32(addrlen, 16);
      if ((src_dst[i] == "src") ^ isRead)
      {
        getsockname(sockfd, addr, addrlen);
      }
      else
      {
        getpeername(sockfd, addr, addrlen);
      }
      message[src_dst[i] + "_port"] = ntohs(Memory.readU16(addr.add(2)));
      message[src_dst[i] + "_addr"] = ntohl(Memory.readU32(addr.add(4)));
    }

    return message;
  }

  /**
   * Get the session_id of SSL object and return it as a hex string.
   * @param {!NativePointer} ssl A pointer to an SSL object.
   * @return {dict} A string representing the session_id of the SSL object's
   *     SSL_SESSION. For example,
   *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
   */
  function getSslSessionId(ssl)
  {
    var session = SSL_get_session(ssl);
    if (session == 0)
    {
      return 0;
    }
    var len = Memory.alloc(4);
    var p = SSL_SESSION_get_id(session, len);
    len = Memory.readU32(len);

    var session_id = "";
    for (var i = 0; i < len; i++)
    {
      // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
      // it to session_id.
      session_id +=
        ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
    }

    return session_id;
  }

  Interceptor.attach(addresses["SSL_read"],
  {
    onEnter: function (args)
    {
      var message = getPortsAndAddresses(SSL_get_fd(args[0]), true);
      message["ssl_session_id"] = getSslSessionId(args[0]);
      message["function"] = "SSL_read";
      this.message = message;
      this.buf = args[1];
    },
    onLeave: function (retval)
    {
      retval |= 0; // Cast retval to 32-bit integer.
      if (retval <= 0)
      {
        return;
      }
      send(this.message, Memory.readByteArray(this.buf, retval));
    }
  });

  Interceptor.attach(addresses["SSL_write"],
  {
    onEnter: function (args)
    {
      var message = getPortsAndAddresses(SSL_get_fd(args[0]), false);
      message["ssl_session_id"] = getSslSessionId(args[0]);
      message["function"] = "SSL_write";
      send(message, Memory.readByteArray(args[1], parseInt(args[2])));
    },

    onLeave: function (retval)
    {
    }
  });
  """


# ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
#                                  <bytes sent by server>)
ssl_sessions = {}


def ssl_log(process, pcap=None, verbose=False, wait=False):
  """Decrypts and logs a process's SSL traffic.

  Hooks the functions SSL_read() and SSL_write() in a given process and logs
  the decrypted data to the console and/or to a pcap file.

  Args:
    process: The target process's name (as a string) or process ID (as an int).
    pcap: The file path to which the pcap file should be written.
    verbose: If True, log the decrypted traffic to the console.

  Raises:
    NotImplementedError: Not running on a Linux or macOS system.
  """

  if platform.system() not in ("Darwin", "Linux"):
    raise NotImplementedError("This function is only implemented for Linux and "
                              "macOS systems.")

  def log_pcap(pcap_file, ssl_session_id, function, src_addr, src_port,
               dst_addr, dst_port, data):
    """Writes the captured data to a pcap file.

    Args:
      pcap_file: The opened pcap file.
      ssl_session_id: The SSL session ID for the communication.
      function: The function that was intercepted ("SSL_read" or "SSL_write").
      src_addr: The source address of the logged packet.
      src_port: The source port of the logged packet.
      dst_addr: The destination address of the logged packet.
      dst_port: The destination port of the logged packet.
      data: The decrypted packet data.
    """
    t = time.time()

    if ssl_session_id not in ssl_sessions:
      ssl_sessions[ssl_session_id] = (random.randint(0, 0xFFFFFFFF),
                                      random.randint(0, 0xFFFFFFFF))
    client_sent, server_sent = ssl_sessions[ssl_session_id]

    if function == "SSL_read":
      seq, ack = (server_sent, client_sent)
    else:
      seq, ack = (client_sent, server_sent)

    for writes in (
        # PCAP record (packet) header
        ("=I", int(t)),                   # Timestamp seconds
        ("=I", (t * 1000000) % 1000000),  # Timestamp microseconds
        ("=I", 40 + len(data)),           # Number of octets saved
        ("=i", 40 + len(data)),           # Actual length of packet
        # IPv4 header
        (">B", 0x45),                     # Version and Header Length
        (">B", 0),                        # Type of Service
        (">H", 40 + len(data)),           # Total Length
        (">H", 0),                        # Identification
        (">H", 0x4000),                   # Flags and Fragment Offset
        (">B", 0xFF),                     # Time to Live
        (">B", 6),                        # Protocol
        (">H", 0),                        # Header Checksum
        (">I", src_addr),                 # Source Address
        (">I", dst_addr),                 # Destination Address
        # TCP header
        (">H", src_port),                 # Source Port
        (">H", dst_port),                 # Destination Port
        (">I", seq),                      # Sequence Number
        (">I", ack),                      # Acknowledgment Number
        (">H", 0x5018),                   # Header Length and Flags
        (">H", 0xFFFF),                   # Window Size
        (">H", 0),                        # Checksum
        (">H", 0)):                       # Urgent Pointer
      pcap_file.write(struct.pack(writes[0], writes[1]))
    pcap_file.write(data)

    if function == "SSL_read":
      server_sent += len(data)
    else:
      client_sent += len(data)
    ssl_sessions[ssl_session_id] = (client_sent, server_sent)

  def on_message(message, data):
    """Callback for errors and messages sent from Frida-injected JavaScript.

    Logs captured packet data received from JavaScript to the console and/or a
    pcap file. See https://www.frida.re/docs/messages/ for more detail on
    Frida's messages.

    Args:
      message: A dictionary containing the message "type" and other fields
          dependent on message type.
      data: The string of captured decrypted data.
    """
    if message["type"] == "error":
      pprint.pprint(message)
      os.kill(os.getpid(), signal.SIGTERM)
      return
    if len(data) == 0:
      return
    p = message["payload"]
    if verbose:
      src_addr = socket.inet_ntop(socket.AF_INET,
                                  struct.pack(">I", p["src_addr"]))
      dst_addr = socket.inet_ntop(socket.AF_INET,
                                  struct.pack(">I", p["dst_addr"]))
      print "SSL Session: " + p["ssl_session_id"]
      print "[%s] %s:%d --> %s:%d" % (
          p["function"],
          src_addr,
          p["src_port"],
          dst_addr,
          p["dst_port"])
      hexdump.hexdump(data)
      print
    if pcap:
      log_pcap(pcap_file, p["ssl_session_id"], p["function"], p["src_addr"],
               p["src_port"], p["dst_addr"], p["dst_port"], data)

  while wait:
    try:
      frida.get_local_device().get_process(process)
      break
    except frida.ProcessNotFoundError:
      time.sleep(0.1)

  session = frida.attach(process)

  if pcap:
    pcap_file = open(pcap, "wb", 0)
    for writes in (
        ("=I", 0xa1b2c3d4),     # Magic number
        ("=H", 2),              # Major version number
        ("=H", 4),              # Minor version number
        ("=i", time.timezone),  # GMT to local correction
        ("=I", 0),              # Accuracy of timestamps
        ("=I", 65535),          # Max length of captured packets
        ("=I", 228)):           # Data link type (LINKTYPE_IPV4)
      pcap_file.write(struct.pack(writes[0], writes[1]))

  script = session.create_script(_FRIDA_SCRIPT)
  script.on("message", on_message)
  script.load()

  print "Press Ctrl+C to stop logging."
  try:
    signal.pause()
  except KeyboardInterrupt:
    pass

  session.detach()
  if pcap:
    pcap_file.close()


if __name__ == "__main__":

  class ArgParser(argparse.ArgumentParser):

    def error(self, message):
      print "ssl_logger v" + __version__
      print "by " + __author__
      print
      print "Error: " + message
      print
      print self.format_help().replace("usage:", "Usage:")
      self.exit(0)

  parser = ArgParser(
      add_help=False,
      description="Decrypts and logs a process's SSL traffic.",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=r"""
Examples:
  %(prog)s -pcap ssl.pcap openssl
  %(prog)s -verbose 31337
  %(prog)s -pcap log.pcap -verbose wget
""")

  args = parser.add_argument_group("Arguments")
  args.add_argument("-pcap", metavar="<path>",
                    help="Name of PCAP file to write")
  args.add_argument("-verbose", action="store_true",
                    help="Show verbose output")
  args.add_argument("-wait", action="store_true",
                    help="Wait for the process")
  args.add_argument("-ssl", metavar="<lib>",
                    help="SSL library to hook (default: *libssl*)")
  args.add_argument("process", metavar="<process name | process id>",
                    help="Process whose SSL calls to log")
  parsed = parser.parse_args()

  if parsed.ssl is not None:
    _FRIDA_SCRIPT = _FRIDA_SCRIPT.replace('*libssl*', parsed.ssl)

  ssl_log(int(parsed.process) if parsed.process.isdigit() else parsed.process,
          parsed.pcap, parsed.verbose, parsed.wait)
