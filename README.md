# uproxy-sctp-throughput
Stress test usrsctp for throughput and reliability.

Some of the defaults are kinda crap
> ./throughput 2048 100 50

Works well.  The first arg is the number of SIDs to use.  The second is the payload size (up to a little under 
64k), and the last is the number of times to use each sid.
