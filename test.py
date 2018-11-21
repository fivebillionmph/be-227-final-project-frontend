import securep2p227 as sp

key = sp.genKey("test-data", "test1")

host = Host("securep2p.fivebillionmph.com")

key.register(host)
