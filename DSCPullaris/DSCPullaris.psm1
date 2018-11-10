$cred = [pscredential]::new('ben', (ConvertTo-SecureString -String '' -AsPlainText -Force))
$null = New-DSCPullServerAdminConnection -SQLServer '' -Credential $cred -Database dsc
$configDirectory = 'C:\Users\BenGelens\Desktop\bla'
$moduleDirectory = 'C:\Users\BenGelens\Desktop\bla'

New-PolarisPutRoute -Path 'Nodes:ID' -Scriptblock {
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
                ConfigurationNames = $Request.Body.ConfigurationNames
                Confirm = $false
            }
            New-DSCPullServerAdminRegistration @newArgs
        } else {
            $updateArgs = @{
                LCMVersion = $Request.Body.AgentInformation.LCMVersion
                NodeName = $Request.Body.AgentInformation.NodeName
                IPAddress = $Request.Body.AgentInformation.IPAddress -split ';' -split ',' | Where-Object -FilterScript {$_ -ne [string]::Empty}
                ConfigurationNames = $Request.Body.ConfigurationNames
                Confirm = $false
            }
            $existingNode | Set-DSCPullServerAdminRegistration @updateArgs
        }
        $Response.StatusCode = 201
        $Response.Headers.Add('ProtocolVersion', '2.0')
    }
}

New-PolarisPostRoute -Path 'Nodes:ID/GetDscAction' -Scriptblock {
    $script:Polaris.Log(($Request.Body | ConvertTo-Json -Depth 100))
    $script:Polaris.Log(($Request.Headers | ConvertTo-Json -Depth 100))

    $agentId = ($Request.Parameters.ID -split '=')[-1].TrimEnd(')').Trim("'")
    $existingNode = Get-DSCPullServerAdminRegistration -AgentId $agentId

    $Response.StatusCode = 200
    $Response.ContentType = 'application/json'
    $Response.Headers.Add('ProtocolVersion', '2.0')

    $responseBody = @{
        NodeStatus = 'GetConfiguration'
        Details = @(
            @{
                ConfigurationName = $existingNode.ConfigurationNames
                Status = 'GetConfiguration'
            }
        )
        
    }
    $response.Json(($responseBody | ConvertTo-Json))
}

New-PolarisGetRoute -Path 'Nodes:ID/Configurations:ConfigName/ConfigurationContent' -Scriptblock {
    $script:Polaris.Log(($Request.Body | ConvertTo-Json -Depth 100))
    $script:Polaris.Log(($Request.Headers | ConvertTo-Json -Depth 100))

    $agentId = ($Request.Parameters.ID -split '=')[-1].TrimEnd(')').Trim("'")
    $configName = ($Request.Parameters.ConfigName -split '=')[-1].TrimEnd(')').Trim("'")

    $Response.Headers.Add('ProtocolVersion', '2.0')

    $file = Get-Item -Path $configDirectory\$configName.mof -ErrorAction SilentlyContinue
    if ($null -eq $file) {
        $Response.StatusCode = 404
    } else {
        $content = $file | Get-Content -Encoding unicode
        $checksum = ($file | Get-FileHash -Algorithm SHA256).Hash

        $fileBytes = [io.file]::ReadAllBytes($file)

        $Response.StatusCode = 200
        $Response.ContentType = 'application/json'
        $Response.Headers.Add('Content-Length', $content.Length)
        $Response.Headers.Add('Checksum', $checkSum)
        $Response.Headers.Add('ChecksumAlgorithm','SHA-256')
        $Response.ByteResponse = $fileBytes
    }
}

$null = Start-Polaris -Port 8081 -UseJsonBodyParserMiddleware
