# ssl_logger

Decrypts and logs a process's SSL traffic.

The functionality offered by *ssl_logger* is intended to mimic [Echo Mirage](http://resources.infosecinstitute.com/echo-mirage-walkthrough/)'s SSL logging functionality on Linux and macOS.

## Basic Usage

`python ssl_logger.py [-pcap <path>] [-verbose] <process name | process id>`

Arguments:

    -pcap <path>                 Name of PCAP file to write
    -verbose                     Show verbose output
    <process name | process id>  Process whose SSL calls to log

Examples:

    ssl_logger.py -pcap ssl.pcap openssl
    ssl_logger.py -verbose 31337
    ssl_logger.py -pcap log.pcap -verbose wget

## Full Example

```
geffner@ubuntu:~$ # Make a local pipe for input to our openssl client
geffner@ubuntu:~$ mkfifo pipe

geffner@ubuntu:~$ # Create our openssl client, which will receive input from our pipe
geffner@ubuntu:~$ openssl s_client -ign_eof -connect example.org:443 > /dev/null 2> /dev/null < pipe &
[1] 98954

geffner@ubuntu:~$ # Begin writing the request to our pipe
geffner@ubuntu:~$ printf "GET / HTTP/1.0\nHost:example.org\n" > pipe

geffner@ubuntu:~$ # Begin logging the SSL traffic for our openssl client process
geffner@ubuntu:~$ python ssl_logger.py -verbose 98954 &
[2] 98962
Press Ctrl+C to stop logging.

geffner@ubuntu:~$ # Write the final line-feed to our pipe to complete the HTTP request
geffner@ubuntu:~$ printf "\n" > pipe
SSL Session: 1820201001719DF42ECCA1D289C3D32E0AA0454B50E8AF00E8A65B0108F209A8
[SSL_write] 100.97.20.44:45836 --> 93.184.216.34:443
00000000: 0A                                                .

SSL Session: 1820201001719DF42ECCA1D289C3D32E0AA0454B50E8AF00E8A65B0108F209A8
[SSL_read] 93.184.216.34:443 --> 100.97.20.44:45836
00000000: 48 54 54 50 2F 31 2E 30  20 32 30 30 20 4F 4B 0D  HTTP/1.0 200 OK.
00000010: 0A 41 63 63 65 70 74 2D  52 61 6E 67 65 73 3A 20  .Accept-Ranges: 
00000020: 62 79 74 65 73 0D 0A 43  61 63 68 65 2D 43 6F 6E  bytes..Cache-Con
00000030: 74 72 6F 6C 3A 20 6D 61  78 2D 61 67 65 3D 36 30  trol: max-age=60
00000040: 34 38 30 30 0D 0A 43 6F  6E 74 65 6E 74 2D 54 79  4800..Content-Ty
00000050: 70 65 3A 20 74 65 78 74  2F 68 74 6D 6C 0D 0A 44  pe: text/html..D
00000060: 61 74 65 3A 20 54 68 75  2C 20 32 32 20 4A 75 6E  ate: Thu, 22 Jun
00000070: 20 32 30 31 37 20 31 35  3A 31 36 3A 35 32 20 47   2017 15:16:52 G
00000080: 4D 54 0D 0A 45 74 61 67  3A 20 22 33 35 39 36 37  MT..Etag: "35967
00000090: 30 36 35 31 22 0D 0A 45  78 70 69 72 65 73 3A 20  0651"..Expires: 
000000A0: 54 68 75 2C 20 32 39 20  4A 75 6E 20 32 30 31 37  Thu, 29 Jun 2017
000000B0: 20 31 35 3A 31 36 3A 35  32 20 47 4D 54 0D 0A 4C   15:16:52 GMT..L
000000C0: 61 73 74 2D 4D 6F 64 69  66 69 65 64 3A 20 46 72  ast-Modified: Fr
000000D0: 69 2C 20 30 39 20 41 75  67 20 32 30 31 33 20 32  i, 09 Aug 2013 2
000000E0: 33 3A 35 34 3A 33 35 20  47 4D 54 0D 0A 53 65 72  3:54:35 GMT..Ser
000000F0: 76 65 72 3A 20 45 43 53  20 28 72 68 76 2F 38 31  ver: ECS (rhv/81
00000100: 38 46 29 0D 0A 56 61 72  79 3A 20 41 63 63 65 70  8F)..Vary: Accep
00000110: 74 2D 45 6E 63 6F 64 69  6E 67 0D 0A 58 2D 43 61  t-Encoding..X-Ca
00000120: 63 68 65 3A 20 48 49 54  0D 0A 43 6F 6E 74 65 6E  che: HIT..Conten
00000130: 74 2D 4C 65 6E 67 74 68  3A 20 31 32 37 30 0D 0A  t-Length: 1270..
00000140: 43 6F 6E 6E 65 63 74 69  6F 6E 3A 20 63 6C 6F 73  Connection: clos
00000150: 65 0D 0A 0D 0A                                    e....

SSL Session: 1820201001719DF42ECCA1D289C3D32E0AA0454B50E8AF00E8A65B0108F209A8
[SSL_read] 93.184.216.34:443 --> 100.97.20.44:45836
00000000: 3C 21 64 6F 63 74 79 70  65 20 68 74 6D 6C 3E 0A  <!doctype html>.
00000010: 3C 68 74 6D 6C 3E 0A 3C  68 65 61 64 3E 0A 20 20  <html>.<head>.  
00000020: 20 20 3C 74 69 74 6C 65  3E 45 78 61 6D 70 6C 65    <title>Example
00000030: 20 44 6F 6D 61 69 6E 3C  2F 74 69 74 6C 65 3E 0A   Domain</title>.
00000040: 0A 20 20 20 20 3C 6D 65  74 61 20 63 68 61 72 73  .    <meta chars
00000050: 65 74 3D 22 75 74 66 2D  38 22 20 2F 3E 0A 20 20  et="utf-8" />.  
00000060: 20 20 3C 6D 65 74 61 20  68 74 74 70 2D 65 71 75    <meta http-equ
00000070: 69 76 3D 22 43 6F 6E 74  65 6E 74 2D 74 79 70 65  iv="Content-type
00000080: 22 20 63 6F 6E 74 65 6E  74 3D 22 74 65 78 74 2F  " content="text/
00000090: 68 74 6D 6C 3B 20 63 68  61 72 73 65 74 3D 75 74  html; charset=ut
000000A0: 66 2D 38 22 20 2F 3E 0A  20 20 20 20 3C 6D 65 74  f-8" />.    <met
000000B0: 61 20 6E 61 6D 65 3D 22  76 69 65 77 70 6F 72 74  a name="viewport
000000C0: 22 20 63 6F 6E 74 65 6E  74 3D 22 77 69 64 74 68  " content="width
000000D0: 3D 64 65 76 69 63 65 2D  77 69 64 74 68 2C 20 69  =device-width, i
000000E0: 6E 69 74 69 61 6C 2D 73  63 61 6C 65 3D 31 22 20  nitial-scale=1" 
000000F0: 2F 3E 0A 20 20 20 20 3C  73 74 79 6C 65 20 74 79  />.    <style ty
00000100: 70 65 3D 22 74 65 78 74  2F 63 73 73 22 3E 0A 20  pe="text/css">. 
00000110: 20 20 20 62 6F 64 79 20  7B 0A 20 20 20 20 20 20     body {.      
00000120: 20 20 62 61 63 6B 67 72  6F 75 6E 64 2D 63 6F 6C    background-col
00000130: 6F 72 3A 20 23 66 30 66  30 66 32 3B 0A 20 20 20  or: #f0f0f2;.   
00000140: 20 20 20 20 20 6D 61 72  67 69 6E 3A 20 30 3B 0A       margin: 0;.
00000150: 20 20 20 20 20 20 20 20  70 61 64 64 69 6E 67 3A          padding:
00000160: 20 30 3B 0A 20 20 20 20  20 20 20 20 66 6F 6E 74   0;.        font
00000170: 2D 66 61 6D 69 6C 79 3A  20 22 4F 70 65 6E 20 53  -family: "Open S
00000180: 61 6E 73 22 2C 20 22 48  65 6C 76 65 74 69 63 61  ans", "Helvetica
00000190: 20 4E 65 75 65 22 2C 20  48 65 6C 76 65 74 69 63   Neue", Helvetic
000001A0: 61 2C 20 41 72 69 61 6C  2C 20 73 61 6E 73 2D 73  a, Arial, sans-s
000001B0: 65 72 69 66 3B 0A 20 20  20 20 20 20 20 20 0A 20  erif;.        . 
000001C0: 20 20 20 7D 0A 20 20 20  20 64 69 76 20 7B 0A 20     }.    div {. 
000001D0: 20 20 20 20 20 20 20 77  69 64 74 68 3A 20 36 30         width: 60
000001E0: 30 70 78 3B 0A 20 20 20  20 20 20 20 20 6D 61 72  0px;.        mar
000001F0: 67 69 6E 3A 20 35 65 6D  20 61 75 74 6F 3B 0A 20  gin: 5em auto;. 
00000200: 20 20 20 20 20 20 20 70  61 64 64 69 6E 67 3A 20         padding: 
00000210: 35 30 70 78 3B 0A 20 20  20 20 20 20 20 20 62 61  50px;.        ba
00000220: 63 6B 67 72 6F 75 6E 64  2D 63 6F 6C 6F 72 3A 20  ckground-color: 
00000230: 23 66 66 66 3B 0A 20 20  20 20 20 20 20 20 62 6F  #fff;.        bo
00000240: 72 64 65 72 2D 72 61 64  69 75 73 3A 20 31 65 6D  rder-radius: 1em
00000250: 3B 0A 20 20 20 20 7D 0A  20 20 20 20 61 3A 6C 69  ;.    }.    a:li
00000260: 6E 6B 2C 20 61 3A 76 69  73 69 74 65 64 20 7B 0A  nk, a:visited {.
00000270: 20 20 20 20 20 20 20 20  63 6F 6C 6F 72 3A 20 23          color: #
00000280: 33 38 34 38 38 66 3B 0A  20 20 20 20 20 20 20 20  38488f;.        
00000290: 74 65 78 74 2D 64 65 63  6F 72 61 74 69 6F 6E 3A  text-decoration:
000002A0: 20 6E 6F 6E 65 3B 0A 20  20 20 20 7D 0A 20 20 20   none;.    }.   
000002B0: 20 40 6D 65 64 69 61 20  28 6D 61 78 2D 77 69 64   @media (max-wid
000002C0: 74 68 3A 20 37 30 30 70  78 29 20 7B 0A 20 20 20  th: 700px) {.   
000002D0: 20 20 20 20 20 62 6F 64  79 20 7B 0A 20 20 20 20       body {.    
000002E0: 20 20 20 20 20 20 20 20  62 61 63 6B 67 72 6F 75          backgrou
000002F0: 6E 64 2D 63 6F 6C 6F 72  3A 20 23 66 66 66 3B 0A  nd-color: #fff;.
00000300: 20 20 20 20 20 20 20 20  7D 0A 20 20 20 20 20 20          }.      
00000310: 20 20 64 69 76 20 7B 0A  20 20 20 20 20 20 20 20    div {.        
00000320: 20 20 20 20 77 69 64 74  68 3A 20 61 75 74 6F 3B      width: auto;
00000330: 0A 20 20 20 20 20 20 20  20 20 20 20 20 6D 61 72  .            mar
00000340: 67 69 6E 3A 20 30 20 61  75 74 6F 3B 0A 20 20 20  gin: 0 auto;.   
00000350: 20 20 20 20 20 20 20 20  20 62 6F 72 64 65 72 2D           border-
00000360: 72 61 64 69 75 73 3A 20  30 3B 0A 20 20 20 20 20  radius: 0;.     
00000370: 20 20 20 20 20 20 20 70  61 64 64 69 6E 67 3A 20         padding: 
00000380: 31 65 6D 3B 0A 20 20 20  20 20 20 20 20 7D 0A 20  1em;.        }. 
00000390: 20 20 20 7D 0A 20 20 20  20 3C 2F 73 74 79 6C 65     }.    </style
000003A0: 3E 20 20 20 20 0A 3C 2F  68 65 61 64 3E 0A 0A 3C  >    .</head>..<
000003B0: 62 6F 64 79 3E 0A 3C 64  69 76 3E 0A 20 20 20 20  body>.<div>.    
000003C0: 3C 68 31 3E 45 78 61 6D  70 6C 65 20 44 6F 6D 61  <h1>Example Doma
000003D0: 69 6E 3C 2F 68 31 3E 0A  20 20 20 20 3C 70 3E 54  in</h1>.    <p>T
000003E0: 68 69 73 20 64 6F 6D 61  69 6E 20 69 73 20 65 73  his domain is es
000003F0: 74 61 62 6C 69 73 68 65  64 20 74 6F 20 62 65 20  tablished to be 

SSL Session: 1820201001719DF42ECCA1D289C3D32E0AA0454B50E8AF00E8A65B0108F209A8
[SSL_read] 93.184.216.34:443 --> 100.97.20.44:45836
00000000: 75 73 65 64 20 66 6F 72  20 69 6C 6C 75 73 74 72  used for illustr
00000010: 61 74 69 76 65 20 65 78  61 6D 70 6C 65 73 20 69  ative examples i
00000020: 6E 20 64 6F 63 75 6D 65  6E 74 73 2E 20 59 6F 75  n documents. You
00000030: 20 6D 61 79 20 75 73 65  20 74 68 69 73 0A 20 20   may use this.  
00000040: 20 20 64 6F 6D 61 69 6E  20 69 6E 20 65 78 61 6D    domain in exam
00000050: 70 6C 65 73 20 77 69 74  68 6F 75 74 20 70 72 69  ples without pri
00000060: 6F 72 20 63 6F 6F 72 64  69 6E 61 74 69 6F 6E 20  or coordination 
00000070: 6F 72 20 61 73 6B 69 6E  67 20 66 6F 72 20 70 65  or asking for pe
00000080: 72 6D 69 73 73 69 6F 6E  2E 3C 2F 70 3E 0A 20 20  rmission.</p>.  
00000090: 20 20 3C 70 3E 3C 61 20  68 72 65 66 3D 22 68 74    <p><a href="ht
000000A0: 74 70 3A 2F 2F 77 77 77  2E 69 61 6E 61 2E 6F 72  tp://www.iana.or
000000B0: 67 2F 64 6F 6D 61 69 6E  73 2F 65 78 61 6D 70 6C  g/domains/exampl
000000C0: 65 22 3E 4D 6F 72 65 20  69 6E 66 6F 72 6D 61 74  e">More informat
000000D0: 69 6F 6E 2E 2E 2E 3C 2F  61 3E 3C 2F 70 3E 0A 3C  ion...</a></p>.<
000000E0: 2F 64 69 76 3E 0A 3C 2F  62 6F 64 79 3E 0A 3C 2F  /div>.</body>.</
000000F0: 68 74 6D 6C 3E 0A                                 html>.
```

## Dependencies
This program uses the [frida](https://www.frida.re/) framework to perform code injection.

Frida can be installed as follows: `sudo pip install frida`

## TODO

 - Add support for processes that communicate via SSL without using [libssl](https://wiki.openssl.org/index.php/Libssl_API).
 - Allow user to run *ssl_logger* before starting the process to be logged.


## Disclaimer

This is not an official Google product.