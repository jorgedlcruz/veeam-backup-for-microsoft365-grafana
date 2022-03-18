#!/bin/bash
##      .SYNOPSIS
##      Grafana Dashboard for Veeam Backup for Microsoft Office 365 v4.0 - Using RestAPI to InfluxDB Script
## 
##      .DESCRIPTION
##      This Script will query the Veeam Backup for Microsoft Office 365 RestAPI and send the data directly to InfluxDB, which can be used to present it to Grafana. 
##      The Script and the Grafana Dashboard it is provided as it is, and bear in mind you can not open support Tickets regarding this project. It is a Community Project
##	
##      .Notes
##      NAME:  veeam_office365.ps1
##      ORIGINAL NAME: veeam_office365.ps1
##      LASTEDIT: 19/08/2020
##      VERSION: 4.0
##      KEYWORDS: Veeam, InfluxDB, Grafana
   
##      .Link
##      https://jorgedelacruz.es/
##      https://jorgedelacruz.uk/

##Allow insecure certificate 
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12

##
# Configurations
##

# Endpoint URL for InfluxDB
$veeamInfluxDBURL="http://localhost" #Your InfluxDB Server, http://FQDN or https://FQDN if using SSL
$veeamInfluxDBPort="8086" #Default Port
$veeamInfluxDB="veeamO365" #Default Database

# Endpoint URL for login action
$veeamUsername="user"
$veeamPassword="password"
$veeamRestServer="https://localhost"
$veeamRestPort="4443" #Default Port

#Get API token
$header = @{
    "Content-Type" = "application/x-www-form-urlencoded"
    "Accept" = "application/json"
}

$body = "grant_type=password&username=$veeamUsername&password=$veeamPassword&refresh_token=%27%27"
$uri = "$($veeamRestServer):$($veeamRestPort)/v4/token"
$token = Invoke-RestMethod -Method POST -header $header -uri $uri -Body $body

$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
    "Accept" = "application/json"
    "Authorization" = "bearer $($token.access_token)"
}

# example queries :
# Invoke-RestMethod -Method Get -Uri "https://localhost:4443/v4/proxies" -Headers $headers

##
# Veeam Backup for Microsoft Office 365 Organization. This part will check on our Organization and retrieve Licensing Information
##
$veeamVBOUri="$($veeamRestServer):$($veeamRestPort)/v4/Organizations"
$veeamVBOUrl = Invoke-RestMethod -Method Get -Uri $veeamVBOUri -Headers $headers
foreach ($org in $veeamVBOUrl)
{
    $veeamOrgName = $org.name
    $veeamOrgId = $org.id

    ## Licensing
    $veeamVBOUri="$($veeamRestServer):$($veeamRestPort)/v4/Organizations/$veeamOrgId/LicensingInformation"
    $veeamLicenseUrl = Invoke-RestMethod -Method Get -Uri $veeamVBOUri -Headers $headers
    $licensedUsers=$veeamLicenseUrl.licensedUsers
    $newUsers=$veeamLicenseUrl.newUsers

    $string = "veeam_office365_organization,veeamOrgName=$veeamOrgName licensedUsers=$licensedUsers,newUsers=$newUsers"
    $string
    Invoke-RestMethod "$($veeamInfluxDBURL):$($veeamInfluxDBPort)/write?db=$veeamInfluxDB" -body $string -Method Post

    ##
    # Veeam Backup for Microsoft Office 365 Users. This part will check the total Users and if they are protected or not
    ##
    $veeamVBOUri="$($veeamRestServer):$veeamRestPort/v4/Organizations/$veeamOrgId/Users"
    $veeamVBOUrl = Invoke-RestMethod -Method Get -Uri $veeamVBOUri -Headers $headers
    foreach ($Id in $veeamVBOUrl.results)
    {
        $Id

        $veeamUserId=$id.id
        $veeamUserName=$id.name -replace '\ ','\'
        $veeamUserBackup=$id.isBackuped
        $veeamUserType=$id.type 

        if ($veeamUserBackup){$protectedUser = 1} else {$protectedUser="2"}
        switch ($veeamUserType)
        {
            "User"   {$typeUser = 1}
            "Shared" {$typeUser = 2}
        }

        $veeamVBOUri="$($veeamRestServer):$veeamRestPort/v4/Organizations/$veeamOrgId/Users/$veeamUserId/onedrives"
        $veeamODUrl= Invoke-RestMethod -Method Get -Uri $veeamVBOUri -Headers $headers
        $veeamUserODName=$veeamODUrl.results.name
        if ($veeamODUrl.results.Count -eq 0){$veeamUserODName="inactive"}

        $string = "veeam_office365_overview_OD,veeamOrgName=$veeamOrgName,veeamUserName=$veeamUserName,veeamUserODName=$veeamUserODName protectedUser=$protectedUser,typeUser=$typeUser"
        $string
        Invoke-RestMethod "$($veeamInfluxDBURL):$($veeamInfluxDBPort)/write?db=$veeamInfluxDB" -body $string -Method Post
    }
    

    ##
    # Veeam Backup for Microsoft Office 365 Backup Repositories. This part will check the capacity and used space of the Backup Repositories
    ##
    $veeamVBOUri="$($veeamRestServer):$veeamRestPort/v4/BackupRepositories"
    $veeamVBOUrl=Invoke-RestMethod -Method Get -Uri $veeamVBOUri -Headers $headers

    foreach ($id in $veeamVBOUrl)
    {
        $repository=$id.name -replace '\ ','\'
        $capacity=$id.capacityBytes
        $freeSpace=$id.freeSpaceBytes
        
        $string = "veeam_office365_repository,repository=$repository capacity=$capacity,freeSpace=$freeSpace"
        $string
        Invoke-RestMethod "$($veeamInfluxDBURL):$($veeamInfluxDBPort)/write?db=$veeamInfluxDB" -body $string -Method Post
    }


    #
    # Veeam Backup for Microsoft Office 365 Backup Proxies. This part will check the Name and Threads Number of the Backup Proxies
    ##
    $veeamVBOUri ="$($veeamRestServer):$veeamRestPort/v4/Proxies"
    $veeamProxyUrl = Invoke-RestMethod -Method Get -Uri $veeamVBOUri -Headers $headers

    foreach ($id in $veeamProxyUrl)
    {
        $hostName=$id.hostName
        $threadsNumber=$id.threadsNumber
        $status=$id.status

        $string = "veeam_office365_proxies,proxies=$hostName,status=$status threadsNumber=$threadsNumber"
        $string
        Invoke-RestMethod "$($veeamInfluxDBURL):$($veeamInfluxDBPort)/write?db=$veeamInfluxDB" -body $string -Method Post
    }       
        


    ##
    # Veeam Backup for Microsoft Office 365 Backup Jobs. This part will check the different Jobs, and the Job Sessions per every Job
    ##
    $veeamVBOUri ="$($veeamRestServer):$veeamRestPort/v4/Jobs"
    $veeamJobsUrl = Invoke-RestMethod -Method Get -Uri $veeamVBOUri -Headers $headers

    foreach ($id in $veeamJobsUrl)
    {
        $nameJob=$id.name -replace '\ ','\'
        $idJob=$id.id
    
        
        # Backup Job Sessions
        $veeamVBOUri="$($veeamRestServer):$veeamRestPort/v4/Jobs/$idJob/JobSessions"
        $veeamJobSessionsUrl=Invoke-RestMethod -Method Get -Uri $veeamVBOUri -Headers $headers
        
        foreach ($jobsession in $veeamJobSessionsUrl)
        {
            $creationTime=$jobsession.creationTime
            $endTime=$jobsession.endTime
            $endTimeUnix= [INT64]((New-TimeSpan -Start ($epoch = [timezone]::CurrentTimeZone.ToLocalTime((get-date "01/01/1970 00:00:00"))) -End ([datetime]::Parse($endTime))).TotalSeconds) *1000000000
            $totalDuration=(new-timespan -Start ([datetime]::Parse($creationTime)) -End ([datetime]::Parse($endTime))).TotalSeconds
            $status=$jobsession.status
            $processingRate=$jobsession.statistics.processingRateBytesPS
            $readRate=$jobsession.statistics.readRateBytesPS
            $writeRate=$jobsession.statistics.writeRateBytesPS
            $transferredData=$jobsession.statistics.transferredDataBytes
            $processedObjects=$jobsession.statistics.processedObjects
            $bottleneck=$jobsession.statistics.bottleneck
            switch ($status)
            {
                "Success" {$jobStatus=1}
                "Warning" {$jobStatus=2}
                "Failed"  {$jobStatus=3}
            }

            $string = "veeam_office365_jobs,veeamjobname=$nameJob,bottleneck=$bottleneck totalDuration=$totalDuration,status=$jobStatus,processingRate=$processingRate,readRate=$readRate,writeRate=$writeRate,transferredData=$transferredData,processedObjects=$processedObjects $endTimeUnix"
            $string
            Invoke-RestMethod "$($veeamInfluxDBURL):$($veeamInfluxDBPort)/write?db=$veeamInfluxDB" -body $string -Method Post
        }
    }

    ##
    # Veeam Backup for Microsoft Office 365 Restore Sessions. This part will check the Number of Restore Sessions
    ##
    $veeamVBOUri="$($veeamRestServer):$veeamRestPort/v4/RestoreSessions"
    $veeamRestoreSessionsUrl = Invoke-RestMethod -Method Get -Uri $veeamVBOUri -Headers $headers

    foreach ($id in $veeamRestoreSessionsUrl.results)
    {
        $name=$id.name -replace '\ ','\'
        $nameJob=$name -replace '\ ','\'
        $organization=$id.organization
        $type=$id.type
        $endTime=$id.endTime
        $endTimeUnix= [INT64]((New-TimeSpan -Start ($epoch = [timezone]::CurrentTimeZone.ToLocalTime((get-date "01/01/1970 00:00:00"))) -End ([datetime]::Parse($endTime))).TotalSeconds) *1000000000
        $result=$id.result
        $initiatedBy=$id.initiatedBy -replace '\\','_'
        $details=$id.details
        
        $itemProcessed = 0
        $itemsSuccess = 0
        $itemsProcessed= ($details |where {$_ -match "processed" }).Split(' ')[0]
        $itemsSuccess=($details |where {$_ -match "success" }).Split(' ')[0]
       

        $string = "veeam_office365_restoresession,organization=$organization,veeamjobname=$nameJob,type=$type,result=$result,initiatedBy=$initiatedBy itemsProcessed=$itemsProcessed,itemsSuccess=$itemsSuccess $endTimeUnix"
        $string
        Invoke-RestMethod "$($veeamInfluxDBURL):$($veeamInfluxDBPort)/write?db=$veeamInfluxDB" -body $string -Method Post

    }
        
}

