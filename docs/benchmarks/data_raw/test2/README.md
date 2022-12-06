# Test 2
Question we wished to answer: CPU usage during DoS attack.

We used the `mmwatch` script to scrape the `/metrics` endpoint of the server.
6 samples were taken for each DoS attack size, each sample representing the average free CPU in the last 30 seconds.
To get the utilization subtract by `100` (inverse).

CSV files contain in the first line the size of the attack.
