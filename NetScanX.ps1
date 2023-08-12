# Import the required module
Import-Module NetTCPIP

# Define the function to query ThreatFox API for an IP address
function Get-ThreatFoxIPInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
        [string]$IPAddress
    )

    $body = @{
        query = "search_ioc"
        search_term = $IPAddress
    } | ConvertTo-Json

    try {
        $response = Invoke-WebRequest -Uri "https://threatfox-api.abuse.ch/api/v1/" -Method Post -Body $body -ContentType "application/json" -ErrorAction Stop

        $responseObject = $response.Content | ConvertFrom-Json

        if ($responseObject.query_status -eq "no_result") {
            return "Secure"
        } else {
            return "Insecure"
        }
    }
    catch {
        Write-Error ("Error querying ThreatFox API for IP " + $IPAddress + ": " + $_.Exception.Message)
        return $null
    }
}

try {
    # Get TCP and UDP connections excluding loopback IP, and check them against ThreatFox
    $results = (Get-NetTCPConnection | Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -ne "127.0.0.1" }) + 
    (Get-NetUDPEndpoint | Where-Object { $_.RemoteAddress -ne "127.0.0.1" }) |
    ForEach-Object {
        $processId = $_.OwningProcess
        $processName = (Get-Process -Id $processId -ErrorAction SilentlyContinue).Name
        $ipAddress = $_.RemoteAddress

        # Skip entries without IP addresses
        if (![string]::IsNullOrEmpty($ipAddress)) {
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
    } | Where-Object { $_.IPAddress -ne $null }

    Write-Host "IPAddress      ThreatFoxResult ProcessID ProcessName"
    Write-Host "---------      --------------- --------- -----------"

    $results | ForEach-Object {
        if ($_.ThreatFoxResult -eq "Insecure") {
            Write-Host ("{0,-15} {1,-15} {2,-10} {3,-10}" -f $_.IPAddress, $_.ThreatFoxResult, $_.ProcessID, $_.ProcessName) -ForegroundColor Red
        } else {
            Write-Host ("{0,-15} {1,-15} {2,-10} {3,-10}" -f $_.IPAddress, $_.ThreatFoxResult, $_.ProcessID, $_.ProcessName) -ForegroundColor Green
        }
    }

    # Ask the user if they want to kill insecure processes
    $response = Read-Host "Do you want to kill insecure processes? (Yes/No)"

    if ($response -eq "Yes" -or $response -eq "Y") {
        $insecureProcesses = $results | Where-Object { $_.ThreatFoxResult -eq "Insecure" }
        foreach ($process in $insecureProcesses) {
            $processId = $process.ProcessID
            $processName = $process.ProcessName
            Write-Host "Killing process $processName with ID $processId..."
            Stop-Process -Id $processId
        }
    }
}
catch {
    Write-Host "An unexpected error occurred: $_"
}