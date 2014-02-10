cookiejack
==========

ARP spoof then session jack within your browser

It's supposed to work by ARP poisoning, waiting for cookie headers from the victim and storing those. Then when you the attacker open a browser and go to the site that the victim was just using, cookiejack will modify your outgoing request to include the stolen "Cookie: xyz" header in your request. This would make session jacking as easy as firing up the script and directing your browser to pages the victim visits. That's the idea at least, but in reality this only seems to work if there's only 1 cookie value like PHPSESSID=fddfjs0jf0834j430. When you start adding more values like those __utmz cookies the request sends fine from the attacker with the headers we want and the server sends all the packets over, but the attacker's browser never sends TCP ACKs back to the server so the page fails to load. If you know what's going on here please chime in.
