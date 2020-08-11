# sslcheck
Several SSL testing scripts that each provided a different type of data as I was learning

# Description
you probably want "ssltester3.py"

Assuming you have a spreadsheet with a list of URLS (no https or http, just the domain), in column 2:

python ssltester3.py sites.xlsx Sheet1 2

You need "a spreadsheet", but it can contain anything if you set "testdata = 1" in the code.   It will use built in dictionary of sites to test for demo.
