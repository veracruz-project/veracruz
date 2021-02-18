#!/usr/bin/env python3

import http.client

c = http.client.HTTPConnection('172.17.0.2', 3017, timeout=3)
c.request("GET", "/")
print(c.getresponse())
