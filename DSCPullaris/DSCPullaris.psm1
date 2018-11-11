$cred = [pscredential]::new('ben', (ConvertTo-SecureString -String '' -AsPlainText -Force))
$null = New-DSCPullServerAdminConnection -SQLServer '' -Credential $cred -Database dsc
$configDirectory = 'C:\Users\BenGelens\Desktop\bla'
$moduleDirectory = 'C:\Users\BenGelens\Desktop\modules'

New-PolarisPutRoute -Path 'Nodes:ID' -Scriptblock {
    $script:Polaris.Log('Node Registration')
    $script:Polaris.Log(($Request.Body | ConvertTo-Json -Depth 100))

    if ($Request.Headers['ProtocolVersion'] -ne '2.0') {
        $Response.StatusCode = 400
        $Response.Send('Client protocol version is invalid.')
    } else {
        $agentId = ($Request.Parameters.ID -split '=')[-1].TrimEnd(')').Trim("'")
        $existingNode = Get-DSCPullServerAdminRegistration -AgentId $agentId
        if ($null -eq $existingNode) {
            $newArgs = @{
                AgentId = $agentId
                LCMVersion = $Request.Body.AgentInformation.LCMVersion
                NodeName = $Request.Body.AgentInformation.NodeName
                IPAddress = $Request.Body.AgentInformation.IPAddress -split ';' -split ',' | Where-Object -FilterScript {$_ -ne [string]::Empty}
                Confirm = $false
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
            }

            # ReportServer registration does not contain ConfigurationNames
            if ($Request.Body.RegistrationInformation.RegistrationMessageType -eq 'ConfigurationRepository') {
                [void] $updateArgs.Add('ConfigurationNames', $Request.Body.ConfigurationNames)
            }

            $existingNode | Set-DSCPullServerAdminRegistration @updateArgs
        }
        $Response.StatusCode = 201
        $Response.Headers.Add('ProtocolVersion', '2.0')
    }
}

New-PolarisPostRoute -Path 'Nodes:ID/GetDscAction' -Scriptblock {
    $script:Polaris.Log('Get Configuration')
    $script:Polaris.Log(($Request.Body | ConvertTo-Json -Depth 100))
    $script:Polaris.Log(($Request.Headers | ConvertTo-Json -Depth 100))

    $agentId = ($Request.Parameters.ID -split '=')[-1].TrimEnd(')').Trim("'")

    $existingNode = Get-DSCPullServerAdminRegistration -AgentId $agentId

    # always respect ConfigurationName in Database? What about partial configs?
    $filePath = (Join-Path -Path $configDirectory -ChildPath $existingNode.ConfigurationNames[0]) + '.mof'
    $file = Get-Item -Path $filePath -ErrorAction SilentlyContinue

    if ($null -eq $file) {
        $script:Polaris.Log('Configuration Document not found, sending OK')
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
            $script:Polaris.Log('Configuration Document checksum same as on client, sending OK')
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
            $script:Polaris.Log('Configuration Document checksum different from on client, sending GetConfiguration')
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

    $Response.StatusCode = 200
    $Response.ContentType = 'application/json'
    $Response.Headers.Add('ProtocolVersion', '2.0')
    $response.Json(($responseBody | ConvertTo-Json))
}

New-PolarisGetRoute -Path 'Nodes:ID/Configurations:ConfigName/ConfigurationContent' -Scriptblock {
    $script:Polaris.Log('Get Configuration Content')
    $script:Polaris.Log(($Request.Body | ConvertTo-Json -Depth 100))
    $script:Polaris.Log(($Request.Headers | ConvertTo-Json -Depth 100))

    $agentId = ($Request.Parameters.ID -split '=')[-1].TrimEnd(')').Trim("'")
    $configName = ($Request.Parameters.ConfigName -split '=')[-1].TrimEnd(')').Trim("'")

    $Response.Headers.Add('ProtocolVersion', '2.0')

    $filePath = (Join-Path -Path $configDirectory -ChildPath $configName) + '.mof'
    $file = Get-Item -Path $filePath -ErrorAction SilentlyContinue
    $script:Polaris.Log($file)

    if ($null -eq $file) {
        $Response.StatusCode = 404
    } else {
        $content = $file | Get-Content -Encoding unicode
        $checksum = ($file | Get-FileHash -Algorithm SHA256).Hash

        $fileBytes = [io.file]::ReadAllBytes($file)

        $Response.StatusCode = 200
        $Response.ContentType = 'application/octet-stream'
        $Response.Headers.Add('Content-Length', $content.Length)
        $Response.Headers.Add('Checksum', $checkSum)
        $Response.Headers.Add('ChecksumAlgorithm','SHA-256')
        $Response.ByteResponse = $fileBytes
    }
}

New-PolarisGetRoute -Path 'Modules:ModuleName,:ModuleVersion/ModuleContent' -Scriptblock {
    $script:Polaris.Log('Get Module Content')
    $script:Polaris.Log(($Request.Body | ConvertTo-Json -Depth 100))
    $script:Polaris.Log(($Request.Headers | ConvertTo-Json -Depth 100))
    $script:Polaris.Log(($Request.Parameters | ConvertTo-Json -Depth 100))

    $moduleName = ($Request.Parameters.ModuleName -split '=')[-1].TrimEnd(')').Trim("'")
    $moduleVersion = ($Request.Parameters.ModuleVersion -split '=')[-1].TrimEnd(')').Trim("'")

    $Response.Headers.Add('ProtocolVersion', '2.0')

    $moduleFullName = $moduleName + '_' + $moduleVersion + '.zip'
    $filePath = Join-Path -Path $moduleDirectory -ChildPath $moduleFullName
    $file = Get-Item -Path $filePath -ErrorAction SilentlyContinue

    $script:Polaris.Log($file)
    if ($null -eq $file) {
        $Response.StatusCode = 404
    } else {
        $content = $file | Get-Content -Encoding unicode
        $checksum = ($file | Get-FileHash -Algorithm SHA256).Hash

        $fileBytes = [io.file]::ReadAllBytes($file)

        $Response.StatusCode = 200
        $Response.ContentType = 'application/octet-stream'
        $Response.Headers.Add('Content-Length', $content.Length)
        $Response.Headers.Add('Checksum', $checkSum)
        $Response.Headers.Add('ChecksumAlgorithm','SHA-256')
        $Response.ByteResponse = $fileBytes
    }
}

$null = Start-Polaris -Port 8081 -UseJsonBodyParserMiddleware
