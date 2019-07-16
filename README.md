[![CircleCI](https://circleci.com/gh/ministryofjustice/securityanalytics-nmapscanner.svg?style=svg)](https://circleci.com/gh/ministryofjustice/securityanalytics-nmapscanner)

# NMAP Scanner

The NMAP scanner is a primary (host) level ECS based scanner. It subscribes to the scan_initiator's scan request outputs and scans the hosts requested. It will port scan the host attempting to detect various vulnerabilities, collating & reporting other information too.

## NSE Plugin support

Currently we are using the following NSE scripts for NMAP

 - ssl-enum-ciphers
 - vulners
 - ssl-cert