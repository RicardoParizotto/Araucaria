# Araucaria
* Araucaria environment

* To reproduce the Araucaria experimens in bmv2 just:

> python3 run.py number_of_hosts bmv2

* To simulate failures, open another terminal run:

> python3 run.py number_of_hosts cli

This will create orphan packets and subsequently drop the switch.

* To run Araucaria in our running example:

> python3 intent_api.py

>> create intent @intentname { functionality : @synchronization [ @size : &3 ], consistency: strong, priority high }
