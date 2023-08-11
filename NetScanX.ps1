# Import the required modules
Import-Module NetTCPIP

# Define the function to query ThreatFox API for an IP address
function Get-ThreatFoxIPInfo {
    param (
        [string]$IPAddress
    )

    $body = @{
        query = "search_ioc"
        search_term = $IPAddress
    } | ConvertTo-Json

    try {
        $response = Invoke-WebRequest -Uri "https://threatfox-api.abuse.ch/api/v1/" -Method POST -Body $body -ContentType "application/json" -ErrorAction Stop

        $responseObject = $response.Content | ConvertFrom-Json

        if ($responseObject.query_status -eq "no_result") {
            $result = "Secure"
        } else {
            $result = "Insecure"
        }

        $result
    }
    catch {
        Write-Host ("Error querying ThreatFox API for IP " + $IPAddress + ": " + $_.Exception.Message)
        $null
    }
}

# Get TCP connections excluding loopback IP
$tcpConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -ne "127.0.0.1" }

# Get UDP connections excluding loopback IP
$udpConnections = Get-NetUDPEndpoint | Where-Object { $_.RemoteAddress -ne "127.0.0.1" }

# Combine TCP and UDP connections
$connections = $tcpConnections + $udpConnections

# Iterate over the connections
$connectionResults = foreach ($conn in $connections) {
    $processId = $conn.OwningProcess
    $processName = (Get-Process -Id $processId -ErrorAction SilentlyContinue).Name
    $ipAddress = $conn.RemoteAddress

    # Skip entries without IP addresses
    if ([string]::IsNullOrEmpty($ipAddress)) {
        continue
    }

    $threatFoxResult = Get-ThreatFoxIPInfo -IPAddress $ipAddress

    if ($threatFoxResult) {
        [PSCustomObject]@{
            IPAddress = $ipAddress
            ThreatFoxResult = $threatFoxResult
            ProcessID = $processId
            ProcessName = $processName
        }
    }
}

# Filter out entries without IP addresses
$filteredResults = $connectionResults | Where-Object { $_.IPAddress -ne $null }

# Format and display the results
if ($filteredResults) {
    $filteredResults | Format-Table -AutoSize
} else {
    Write-Host "No insecure connections found."
}