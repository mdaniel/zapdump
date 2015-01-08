# What
A utility to export OWASP ZAP databases as Scrapy filesystem cache directories

# How
```sh
mvn -e clean package
mvn dependency:copy -DoutputDirectory=target -Dartifact=org.hsqldb:hsqldb:2.2.9
java -jar target/dumper-1.0.jar -dump myawesome.session
find .scrapy/httpcache/myawesome.session -type f
```

# Why
OWASP ZAP is a great tool, and very kindly holds on to every byte it sees,
but harvesting those bytes and putting them into a directory that [Scrapy](http://scrapy.org)
understands is tedious. Tedium is great for computers, so here we are.

It's a glorified script, so don't expect the pinnacle of software engineering
although there are a few tests ... for my sanity.

# Details
It operates in two basic modes: dump the world and dump just a specific URL.

Dump the world does what you'd expect, and is the `-dump` argument.

Dump just a specific URL is also what you'd expect, modulo that the URL you
specify must match **exactly** with what's in the ZAP database.
This mode will not output any files if the URL you specified was found, but
ZAP has no bytes for it (in a 301 redirect, for example).

For convenience the tool also emits a tab separated file of the interesting columns
from the ZAP database. It will put the Scrapy cache hash in the `FINGERPRINT` column
if one was produced.
