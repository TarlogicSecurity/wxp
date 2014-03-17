wxp - W{ireless|onderful} eXfiltration Protocol library
===

The following project is actually a solution containing a set of three different VS 2012 projects, namely:

* wxplib
    This is the WXP library implementing the WXP API. All projects using WXP features must link against the file wxplib.lib in its Release folder.
    
* wxp-sample-udpclient
    This is a sample WXP client working on top of UDP sockets. It tries to connect to a server in 127.0.0.1:9999 and sends the standard output and error and, at the same time, receives commands from it.
    
* wxp-sample-udpserver
    This is the reverse shell listener at *:9999. It displays the received standard output/error in white and the standard input in green. All comands are sent back to the client.
    
Although the software works seamlessly it's still highly experimental. If you find a bug don't hesitate to tell us or send a patch, we'll be glad to review it!
