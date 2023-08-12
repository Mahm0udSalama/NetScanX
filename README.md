

NetScanX is a PowerShell script that utilizes the NetTCPIP module to scan TCP and UDP connections based on the Internet Protocol (IP) and checks them against the ThreatFox API service to determine whether the IP addresses are secure or insecure. The script performs the following steps:

1. Importing the required module:
   The script begins by importing the NetTCPIP module, which provides the necessary cmdlets for working with TCP/IP connections in PowerShell.

2. Defining the function to query ThreatFox API for an IP address:
   The script defines a function named Get-ThreatFoxIPInfo. This function takes an IP address as a mandatory parameter and queries the ThreatFox API to gather information about the IP address.

3. Querying ThreatFox API for each IP address:
   The script retrieves the established TCP connections and UDP endpoints, excluding the loopback IP (127.0.0.1). For each connection, it retrieves the owning process ID, process name, and remote IP address.

4. Skipping entries without IP addresses:
   The script checks if the IP address is not null or empty. If it is, the entry is skipped.

5. Querying ThreatFox for IP information:
   The script calls the Get-ThreatFoxIPInfo function to query the ThreatFox API for each IP address obtained in the previous step. It passes the IP address as a parameter and receives a result indicating whether the IP address is secure or insecure.

6. Displaying the results:
   The script displays the results in a tabular format, showing the IP address, ThreatFox result (secure or insecure), process ID, and process name. Insecure results are displayed in red, while secure results are displayed in green.

7. Prompting user to kill insecure processes:
   After displaying the results, the script prompts the user with a question asking whether they want to kill insecure processes.

8. Killing insecure processes:
   If the user responds with "Yes" or "Y," the script identifies the insecure processes from the results and proceeds to kill them using the Stop-Process cmdlet.

Overall, NetScanX provides a convenient way to scan TCP and UDP connections and check their IP addresses against the ThreatFox API for security analysis. It helps identify insecure processes and offers the option to terminate them if desired.
