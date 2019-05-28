#requires -modules @{ModuleName = 'DSCPullServerAdmin'; ModuleVersion = '0.4.3'}
#requires -modules @{ModuleName = 'Polaris'; ModuleVersion = '0.2.0'}
#requires -version 5.1
using module DSCPullServerAdmin
using module Polaris

class Pullaris {
    [string] $ConfigurationDirectory
    [string] $ModuleDirectory
    [guid[]] $AuthorizationKey
    [DSCPullServerConnection] $Connection
    [Polaris] $Polaris

    Pullaris ($configurationDirectory, $moduleDirectory, $authorizationKey, $connection, $polaris) {
        $this.ConfigurationDirectory = $configurationDirectory
        $this.ModuleDirectory = $moduleDirectory
        $this.AuthorizationKey = $authorizationKey
        $this.Connection = $connection
        $this.Polaris = $polaris

        $this.Polaris.Logger = {
            param($LogItem)
            Write-Host $LogItem
        }
    }

    hidden [bool] TestClientHeader ($Request) {
        return ($Request.Headers['ProtocolVersion'] -eq '2.0')
    }

    hidden [bool] TestClientRegistrationKey ($Request) {
        $xmsdate = $Request.Headers['x-ms-date']
        $auth = $Request.Headers['Authorization'] -replace 'Shared '

        $sha = [System.Security.Cryptography.SHA256]::Create()

        $digB64 = [System.Convert]::ToBase64String(
            $sha.ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($Request.BodyString)
            )
        )

        $sigString = "{0}`n{1}" -f $digB64, $xmsdate

        foreach ($key in $this.AuthorizationKey) {
            $mac = [System.Security.Cryptography.HMACSHA256]::new(
                [System.Text.Encoding]::UTF8.GetBytes($key)
            )

            $sigB64 = [Convert]::ToBase64String(
                $mac.ComputeHash(
                    [System.Text.Encoding]::UTF8.GetBytes($sigString)
                )
            )

            if ($sigB64 -eq $auth) {
                return $true
            }
        }
        return $false
    }

    hidden [void] SetHeader ($Response, $StatusCode, [hashtable] $Headers) {
        [void]$Response.Headers.Add('ProtocolVersion', '2.0')
        [void]$Response.Headers.Add('X-Content-Type-Options', 'nosniff')
        [void]$Response.Headers.Add('Cache-Control', 'no-cache')
        $Response.StatusCode = $StatusCode

        if ($null -ne $Headers) {
            $Headers.GetEnumerator().ForEach{
                [void]$Response.Headers.Add($_.Name, $_.Value)
            }
        }
    }

    hidden [bool] IsClientValid ($AgentId) {
        return ($null -ne (Get-DSCPullServerAdminRegistration -AgentId $AgentId -Connection $this.Connection))
    }
}

$registrationRoute = {
    $pullaris = Get-Pullaris

    $agentId = $Request.Parameters.ID

    if (-not ($pullaris.TestClientHeader($Request))) {
        $pullaris.SetHeader($Response, 400, $null)
        $Response.Send('Client protocol version is invalid.')
    } elseif (-not ($pullaris.TestClientRegistrationKey($Request))) {
        $pullaris.SetHeader($Response, 404, $null)
        $Response.Send('Unauthorized!')
    } else {
        $existingNode = Get-DSCPullServerAdminRegistration -AgentId $agentId -Connection $pullaris.Connection
        if ($null -eq $existingNode) {
            $newArgs = @{
                AgentId = $AgentId
                LCMVersion = $Request.Body.AgentInformation.LCMVersion
                NodeName = $Request.Body.AgentInformation.NodeName
                IPAddress = $Request.Body.AgentInformation.IPAddress -split ';' -split ',' | Where-Object -FilterScript {$_ -ne [string]::Empty}
                Confirm = $false
                Connection = $pullaris.Connection
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
                Connection = $pullaris.Connection
            }

            # ReportServer registration does not contain ConfigurationNames
            if ($Request.Body.RegistrationInformation.RegistrationMessageType -eq 'ConfigurationRepository') {
                [void] $updateArgs.Add('ConfigurationNames', $Request.Body.ConfigurationNames)
            }

            $existingNode | Set-DSCPullServerAdminRegistration @updateArgs
        }
        $pullaris.SetHeader($Response, 204, $null)
        $Response.Send($null)
    }
}

$actionRoute = {
    $agentId = $Request.Parameters.ID
    $pullaris = Get-Pullaris
    if (-not ($pullaris.TestClientHeader($Request))) {
        $pullaris.SetHeader($Response, 400, $null)
        $Response.Send('Client protocol version is invalid.')
    } elseif (-not $pullaris.IsClientValid($agentId)) {
        $pullaris.SetHeader($Response, 404, $null)
        $Response.Send('Unauthorized Client!')
    } else {
        $existingNode = Get-DSCPullServerAdminRegistration -AgentId $agentId -Connection $pullaris.Connection
    
        # always respect ConfigurationName in Database? What about partial configs?
        $filePath = (Join-Path -Path $pullaris.ConfigurationDirectory -ChildPath $existingNode.ConfigurationNames[0]) + '.mof'
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
        $pullaris.SetHeader($Response, 200, $null)
        $response.Json(($responseBody | ConvertTo-Json))
    }
}

$configurationRoute = {
    $agentId = $Request.Parameters.ID
    $configName = $Request.Parameters.ConfigName
    $pullaris = Get-Pullaris
    if (-not ($pullaris.TestClientHeader($Request))) {
        $pullaris.SetHeader($Response, 400, $null)
        $Response.Send('Client protocol version is invalid.')
    } elseif (-not $pullaris.IsClientValid($agentId)) {
        $pullaris.SetHeader($Response, 404, $null)
        $Response.Send('Unauthorized Client!')
    } else {
        $filePath = (Join-Path -Path $pullaris.ConfigurationDirectory -ChildPath $configName) + '.mof'
        $file = Get-Item -Path $filePath -ErrorAction SilentlyContinue

        if ($null -eq $file) {
            $pullaris.SetHeader($Response, 404, $null)
        } else {
            $content = $file | Get-Content -Encoding unicode
            $checksum = ($file | Get-FileHash -Algorithm SHA256).Hash

            $fileBytes = [io.file]::ReadAllBytes($file)

            $pullaris.SetHeader($Response, 200, @{
                'Content-Length' = $content.Length
                'Checksum' = $checkSum
                'ChecksumAlgorithm' = 'SHA-256'
            })

            $Response.ContentType = 'application/octet-stream'
            $Response.ByteResponse = $fileBytes
        }
    }
}

$moduleRoute = {
    $agentId = $Request.Headers['AgentId']
    $moduleName = $Request.Parameters.ModuleName
    $moduleVersion = $Request.Parameters.ModuleVersion

    $pullaris = Get-Pullaris
    if (-not ($pullaris.TestClientHeader($Request))) {
        $pullaris.SetHeader($Response, 400, $null)
        $Response.Send('Client protocol version is invalid.')
    } elseif (-not $pullaris.IsClientValid($agentId)) {
        $pullaris.SetHeader($Response, 404, $null)
        $Response.Send('Unauthorized Client!')
    } else {
        $moduleFullName = $moduleName + '_' + $moduleVersion + '.zip'
        $filePath = Join-Path -Path $pullaris.ModuleDirectory -ChildPath $moduleFullName
        $file = Get-Item -Path $filePath -ErrorAction SilentlyContinue

        if ($null -eq $file) {
            $pullaris.SetHeader($Response, 404, $null)
        } else {
            $content = $file | Get-Content -Encoding unicode
            $checksum = ($file | Get-FileHash -Algorithm SHA256).Hash

            $fileBytes = [io.file]::ReadAllBytes($file)

            $pullaris.SetHeader($Response, 200, @{
                'Content-Length' = $content.Length
                'Checksum' = $checkSum
                'ChecksumAlgorithm' = 'SHA-256'
            })

            $Response.ContentType = 'application/octet-stream'
            $Response.ByteResponse = $fileBytes
        }
    }
}

$reportRoute = {
    $agentId = $Request.Parameters.ID
    $jobId = $Request.Body.JobId

    $pullaris = Get-Pullaris
    if (-not ($pullaris.TestClientHeader($Request))) {
        $pullaris.SetHeader($Response, 400, $null)
        $Response.Send('Client protocol version is invalid.')
    } elseif (-not $pullaris.IsClientValid($agentId)) {
        $pullaris.SetHeader($Response, 404, $null)
        $Response.Send('Unauthorized Client!')
    } else {
        $reportArgs = @{}
        $Request.Body.psobject.properties.ForEach{ $reportArgs[$_.Name] = $_.Value }

        if ($reportArgs.ContainsKey('IPAddress')) {
            $reportArgs.IPAddress = $reportArgs.IPAddress -split ';' -split ',' | Where-Object -FilterScript {$_ -ne [string]::Empty}
        }

        if ($reportArgs.ContainsKey('RebootRequested')) {
            $reportArgs.RebootRequested = $reportArgs.RebootRequested.ToBoolean($_)
        }

        $pullaris.Polaris.Log(($reportArgs | Out-String))
        $existingReport = Get-DSCPullServerAdminStatusReport -JobId $jobId -AgentId $agentId -Connection $pullaris.Connection
        if ($null -eq $existingReport) {
            $pullaris.Polaris.Log('Creating new Report')
            New-DSCPullServerAdminStatusReport @reportArgs -Id $agentId -Connection $pullaris.Connection -Confirm:$false
        } else {
            $pullaris.Polaris.Log('Updating Existing Report')
            $reportArgs.GetEnumerator().ForEach{
                $existingReport."$($_.Name)" = $_.value
            }
            $existingReport | Set-DSCPullServerAdminStatusReport -Connection $pullaris.Connection -Confirm:$false
        }

        $pullaris.SetHeader($Response, 200, $null)
    }
}

function Start-Pullaris {
    [cmdletbinding()]
    param (
        [Parameter()]
        [uint16] $Port = 8080,

        [Parameter(Mandatory)]
        [DSCPullServerConnection] $DatabaseConnection,

        [Parameter(Mandatory)]
        [System.IO.DirectoryInfo] $ConfigurationDirectory,

        [Parameter(Mandatory)]
        [System.IO.DirectoryInfo] $ModuleDirectory,

        [Parameter(Mandatory)]
        [guid[]] $AuthorizationKey
    )

    if ($null -ne $script:pullaris) {
        Write-Error -Message 'An instance of Pullaris is already running. You can only run a single Pullaris instance per PowerShell session!' -ErrorAction Stop
    }

    $script:pullaris = [Pullaris]::new(
        $ConfigurationDirectory,
        $ModuleDirectory,
        $AuthorizationKey,
        $DatabaseConnection,
        (Start-Polaris -Port $Port -UseJsonBodyParserMiddleware)
    )

    @(
        @{
            Path = "/api/Nodes\(AgentId=':ID'\)"
            Method = 'PUT'
            Scriptblock = $script:registrationRoute
        }
        @{
            Path = "/api/Nodes\(AgentId=':ID'\)/GetDscAction"
            Method = 'POST'
            Scriptblock = $script:actionRoute
        }
        @{
            Path = "/api/Nodes\(AgentId=':ID'\)/Configurations\(ConfigurationName=':ConfigName'\)/ConfigurationContent"
            Method = 'GET'
            Scriptblock = $script:configurationRoute
        }
        @{
            Path = "/api/Modules\(ModuleName=':ModuleName',ModuleVersion=':ModuleVersion'\)/ModuleContent"
            Method = 'GET'
            Scriptblock = $script:moduleRoute
        }
        @{
            Path = "/api/Nodes\(AgentId=':ID'\)/SendReport"
            Method = 'POST'
            Scriptblock = $script:reportRoute
        }
    ).ForEach{
        New-PolarisRoute @_ -Polaris $script:pullaris.Polaris
    }

    Get-Pullaris
}

function Stop-Pullaris {
    if ($null -ne $script:pullaris) {
        Stop-Polaris
        Clear-Polaris
        $script:pullaris = $null
    }
}

function Get-Pullaris {
    [OutputType([Pullaris])]
    [CmdletBinding()]
    param (

    )
    if ($null -ne $script:pullaris) {
        $script:pullaris
    }
}

Export-ModuleMember -Function *Pullaris*
