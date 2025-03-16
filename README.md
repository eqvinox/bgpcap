pcapngsplit
===========

This tool:

* reads a pcapng capture
* does TCP reassembly
* fishes out TCP streams that are "complete" in that they include the beginning
* "selects" one side of the conversation based on excluding the "local" side (identified by list of local IP addresses)
* cuts them up at BGP message boundaries
* writes out each BGP session to a separate pcapng directory / file

build
-----

You need a compiled FRR source / tree to build this.  Look at Makefile.
It expects frr to be in ../frr.  No special ./configure options are needed,
just build FRR.


replay.py
=========

This tool:

* opens some of the pcapng files written above
* opens TCP connections "to match"
* feeds BGP messages back in, while keeping "global order" between the multiple pcapng input files
  * timing is ignored, only order is retained


pcap-ng DLT & IETF draft
========================

The pcap-packet-per-BGP-message stuff uses DLT 147 ("LINKTYPE_USER0").  The
draft is a rough attempt to describe a (somewhat extended) version of what is
going on here.  But it's not clear yet what exactly should be specified here.
