$cred = [pscredential]::new('ben', (ConvertTo-SecureString -String 'bla' -AsPlainText -Force))
$session = New-DSCPullServerAdminConnection -SQLServer 'dscpull' -Credential $cred -Database dsc -DontStore

$configDirectory = 'C:\Users\Administrator\pullaris\Configurations'
$moduleDirectory = 'C:\Users\Administrator\pullaris\Modules'

function Test-DSCCLientHeader {
    param (
        $Request
    )
    if ($Request.Headers['ProtocolVersion'] -ne '2.0') {
        $false
    } else {
        $true
    }
}

function Set-DSCServerHeader {
    param (
        $Response,
        $StatusCode,
        [hashtable]$Headers
    )
    [void]$Response.Headers.Add('ProtocolVersion', '2.0')
    [void]$Response.Headers.Add('X-Content-Type-Options', 'nosniff')
    [void]$Response.Headers.Add('Cache-Control', 'no-cache')
    $Response.StatusCode = $StatusCode

    if ($PSBoundParameters.ContainsKey('Headers')) {
        $Headers.GetEnumerator().ForEach{
            [void]$Response.Headers.Add($_.Name, $_.Value)
        }
    }
}

New-PolarisPutRoute -Path "/api/Nodes\(AgentId=':ID'\)" -Scriptblock {
    $agentId = $Request.Parameters.ID

    if (-not (Test-DSCCLientHeader -Request $Request)) {
        Set-DSCServerHeader -Response $Response -StatusCode 400
        $Response.Send('Client protocol version is invalid.')
    } else {
        $existingNode = Get-DSCPullServerAdminRegistration -AgentId $agentId -Connection $session
        if ($null -eq $existingNode) {
            $newArgs = @{
                AgentId = $AgentId
                LCMVersion = $Request.Body.AgentInformation.LCMVersion
                NodeName = $Request.Body.AgentInformation.NodeName
                IPAddress = $Request.Body.AgentInformation.IPAddress -split ';' -split ',' | Where-Object -FilterScript {$_ -ne [string]::Empty}
                Confirm = $false
                Connection = $session
            }

            # ReportServer registration does not contain ConfigurationNames
            if ($Request.Body.RegistrationInformation.RegistrationMessageType -eq 'ConfigurationRepository') {
                [void] $newArgs.Add('ConfigurationNames', $Request.Body.ConfigurationNames)
            }

            New-DSCPullServerAdminRegistration @newArgs
        } else {
            $updateArgs = @{
                LCMVersion = $Request.Body.AgentInformation.LCMVersion
                NodeName = $Request.Body.AgentInformation.NodeName
                IPAddress = $Request.Body.AgentInformation.IPAddress -split ';' -split ',' | Where-Object -FilterScript {$_ -ne [string]::Empty}
                Confirm = $false
                Connection = $session
            }

            # ReportServer registration does not contain ConfigurationNames
            if ($Request.Body.RegistrationInformation.RegistrationMessageType -eq 'ConfigurationRepository') {
                [void] $updateArgs.Add('ConfigurationNames', $Request.Body.ConfigurationNames)
            }

            $existingNode | Set-DSCPullServerAdminRegistration @updateArgs
        }
        Set-DSCServerHeader -Response $Response -StatusCode 204
    }
}

New-PolarisPostRoute -Path "/api/Nodes\(AgentId=':ID'\)/GetDscAction" -Scriptblock {
    # TODO: Validate if agent is registered
    $agentId = $Request.Parameters.ID

    if (-not (Test-DSCCLientHeader -Request $Request)) {
        Set-DSCServerHeader -Response $Response -StatusCode 400
        $Response.Send('Client protocol version is invalid.')
    } else {
        $existingNode = Get-DSCPullServerAdminRegistration -AgentId $agentId -Connection $session

        # always respect ConfigurationName in Database? What about partial configs?
        $filePath = (Join-Path -Path $configDirectory -ChildPath $existingNode.ConfigurationNames[0]) + '.mof'
        $file = Get-Item -Path $filePath -ErrorAction SilentlyContinue

        if ($null -eq $file) {
            # send OK, even when file is not found
            $responseBody = @{
                NodeStatus = 'Ok'
                Details = @(
                    @{
                        ConfigurationName = $existingNode.ConfigurationNames
                        Status = 'Ok'
                    }
                )
            }
        } else {
            $checksum = ($file | Get-FileHash -Algorithm SHA256).Hash
            if ($Request.Body.ClientStatus.Checksum -eq $checksum) {
                $responseBody = @{
                    NodeStatus = 'Ok'
                    Details = @(
                        @{
                            ConfigurationName = $existingNode.ConfigurationNames
                            Status = 'Ok'
                        }
                    )
                }
            } else {
                $responseBody = @{
                    NodeStatus = 'GetConfiguration'
                    Details = @(
                        @{
                            ConfigurationName = $existingNode.ConfigurationNames
                            Status = 'GetConfiguration'
                        }
                    )
                }
            }
        }
        Set-DSCServerHeader -Response $Response -StatusCode 200
        $response.Json(($responseBody | ConvertTo-Json))
    }
}

New-PolarisGetRoute -Path "/api/Nodes\(AgentId=':ID'\)/Configurations\(ConfigurationName=':ConfigName'\)/ConfigurationContent" -Scriptblock {
    # TODO: Validate if agent is registered
    $agentId = $Request.Parameters.ID
    $configName = $Request.Parameters.ConfigName

    if (-not (Test-DSCCLientHeader -Request $Request)) {
        Set-DSCServerHeader -Response $Response -StatusCode 400
        $Response.Send('Client protocol version is invalid.')
    } else {
        $filePath = (Join-Path -Path $configDirectory -ChildPath $configName) + '.mof'
        $file = Get-Item -Path $filePath -ErrorAction SilentlyContinue

        if ($null -eq $file) {
            Set-DSCServerHeader -StatusCode 404
        } else {
            $content = $file | Get-Content -Encoding unicode
            $checksum = ($file | Get-FileHash -Algorithm SHA256).Hash

            $fileBytes = [io.file]::ReadAllBytes($file)

            Set-DSCServerHeader -Response $Response -StatusCode 200 -Headers @{
                'Content-Length' = $content.Length
                'Checksum' = $checkSum
                'ChecksumAlgorithm' = 'SHA-256'
            }

            $Response.ContentType = 'application/octet-stream'
            $Response.ByteResponse = $fileBytes
        }
    }
}

New-PolarisGetRoute -Path "/api/Modules\(ModuleName=':ModuleName',ModuleVersion=':ModuleVersion'\)/ModuleContent" -Scriptblock {
    # TODO: Validate if agent is registered
    $agentId = $Request.Headers['AgentId']
    $moduleName = $Request.Parameters.ModuleName
    $moduleVersion = $Request.Parameters.ModuleVersion

    if (-not (Test-DSCCLientHeader -Request $Request)) {
        Set-DSCServerHeader -Response $Response -StatusCode 400
        $Response.Send('Client protocol version is invalid.')
    } else {
        $moduleFullName = $moduleName + '_' + $moduleVersion + '.zip'
        $filePath = Join-Path -Path $moduleDirectory -ChildPath $moduleFullName
        $file = Get-Item -Path $filePath -ErrorAction SilentlyContinue

        if ($null -eq $file) {
            Set-DSCServerHeader -StatusCode 404
        } else {
            $content = $file | Get-Content -Encoding unicode
            $checksum = ($file | Get-FileHash -Algorithm SHA256).Hash

            $fileBytes = [io.file]::ReadAllBytes($file)

            Set-DSCServerHeader -Response $Response -StatusCode 200 -Headers @{
                'Content-Length' = $content.Length
                'Checksum' = $checkSum
                'ChecksumAlgorithm' = 'SHA-256'
            }

            $Response.ContentType = 'application/octet-stream'
            $Response.ByteResponse = $fileBytes
        }
    }
}

New-PolarisPostRoute -Path "/api/Nodes\(AgentId=':ID'\)/SendReport" -Scriptblock {
    # TODO: Validate if agent is registered
    $agentId = $Request.Parameters.ID
    $jobId = $Request.Body.JobId

    if (-not (Test-DSCCLientHeader -Request $Request)) {
        Set-DSCServerHeader -Response $Response -StatusCode 400
        $Response.Send('Client protocol version is invalid.')
    } else {
        $reportArgs = @{}
        $Request.Body.psobject.properties.ForEach{ $reportArgs[$_.Name] = $_.Value }

        if ($reportArgs.ContainsKey('IPAddress')) {
            $reportArgs.IPAddress = $reportArgs.IPAddress -split ';' -split ',' | Where-Object -FilterScript {$_ -ne [string]::Empty}
        }

        if ($reportArgs.ContainsKey('RebootRequested')) {
            $reportArgs.RebootRequested = $reportArgs.RebootRequested.ToBoolean($_)
        }

        $script:Polaris.Log(($reportArgs | Out-String))
        $existingReport = Get-DSCPullServerAdminStatusReport -JobId $jobId -AgentId $agentId -Connection $session
        if ($null -eq $existingReport) {
            $script:Polaris.Log('Creating new Report')
            New-DSCPullServerAdminStatusReport @reportArgs -Id $agentId -Connection $session -Confirm:$false
        } else {
            $script:Polaris.Log('Updating Existing Report')
            $reportArgs.GetEnumerator().ForEach{
                $existingReport."$($_.Name)" = $_.value
            }
            $existingReport | Set-DSCPullServerAdminStatusReport -Connection $session -Confirm:$false
        }

        Set-DSCServerHeader -Response $Response -StatusCode 200
    }
}

$pol = Get-Polaris
$pol.Logger = {
    param($LogItem)
    Write-Host $LogItem
}

$null = Start-Polaris -Port 8081 -UseJsonBodyParserMiddleware -Verbose
