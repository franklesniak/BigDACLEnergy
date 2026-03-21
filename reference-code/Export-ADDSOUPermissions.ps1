# .SYNOPSIS
# Exports Active Directory Domain Services (AD DS) organizational unit (OU)
# permissions to a CSV file.
#
# .DESCRIPTION
# This script enumerates all organizational units (OUs) in the current
# computer's Active Directory domain and exports their access control entries
# (ACEs) to a CSV file. It also identifies and reports any unresolved GUIDs
# found in the ACEs, which may indicate orphaned schema extensions from
# previously deployed applications (e.g., Lync/Skype for Business).
#
# The script pins all Active Directory queries to the domain of the computer
# on which it is running to avoid cross-domain issues in multi-domain forests.
#
# .EXAMPLE
# .\Export-ADDSOUPermissions.ps1
#
# Runs the script in the current directory. Produces two output files:
# - OUPermissions.csv: Contains all OU permission entries sorted by
#   CanonicalName and other fields.
# - UnresolvedGUIDs.csv: Contains any GUIDs that could not be resolved to
#   schema attributes or extended rights (only created if unresolved GUIDs
#   exist).
#
# .INPUTS
# None. This script does not accept pipeline input.
#
# .OUTPUTS
# None. This script writes CSV files to disk and does not return objects to
# the pipeline. The internal Export-ADDSOUPermission function returns an
# integer status code, but it is intentionally suppressed at the script
# level using [void].
#
# .NOTES
# This script's design target is Windows PowerShell 1.0 with .NET
# Framework 2.0 or newer, through Windows PowerShell 5.1 with .NET
# Framework 4.8 or newer, and PowerShell 7.x on Windows (via the
# Windows PowerShell Compatibility layer). Windows only.
#
# PowerShell Core 6.x is not expected to function because the RSAT
# ActiveDirectory module is a Windows PowerShell module that requires
# the Windows PowerShell Compatibility layer, which is available in
# PowerShell 7.x but not in PowerShell Core 6.x. Additionally, even
# after the planned migration to System.DirectoryServices .NET classes,
# PowerShell Core 6.x will remain unsupported because it runs on .NET
# Core 2.x, which does not include System.DirectoryServices by default.
#
# However, the script currently requires PowerShell v2.0+ and the RSAT
# ActiveDirectory module because it depends on ActiveDirectory module
# cmdlets (Get-ADDomain, Get-ADObject, Get-ADOrganizationalUnit,
# Get-ADRootDSE). A planned migration will replace these cmdlets with
# [System.DirectoryServices.DirectoryEntry] and
# [System.DirectoryServices.DirectorySearcher] .NET classes (available in
# .NET Framework 2.0), achieving true PowerShell v1.0 compatibility and
# enabling the script to run on any domain member server without requiring
# RSAT. This migration is tracked separately.
#
# Version: 1.1.20260316.1

# Export-ADDSOUPermissions

#region License
###############################################################################
# Copyright 2022-2026 Frank Lesniak

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
###############################################################################
#endregion License

#region Functions
function Get-PSVersion {
    # .SYNOPSIS
    # Returns the version of PowerShell that is running.
    #
    # .DESCRIPTION
    # The function outputs a [version] object representing the version of
    # PowerShell that is running. This function detects the PowerShell
    # runtime version but does not detect the underlying .NET Framework or
    # .NET Core version.
    #
    # On versions of PowerShell greater than or equal to version 2.0, this
    # function returns the equivalent of $PSVersionTable.PSVersion
    #
    # PowerShell 1.0 does not have a $PSVersionTable variable, so this
    # function returns [version]('1.0') on PowerShell 1.0.
    #
    # .EXAMPLE
    # $versionPS = Get-PSVersion
    # # $versionPS now contains the version of PowerShell that is running.
    # # On versions of PowerShell greater than or equal to version 2.0,
    # # this function returns the equivalent of $PSVersionTable.PSVersion.
    #
    # .EXAMPLE
    # $versionPS = Get-PSVersion
    # if ($versionPS.Major -ge 2) {
    #     Write-Host "PowerShell 2.0 or later detected"
    # } else {
    #     Write-Host "PowerShell 1.0 detected"
    # }
    # # This example demonstrates storing the returned version object in a
    # # variable and using it to make conditional decisions based on
    # # PowerShell version. The returned [version] object has properties
    # # like Major, Minor, Build, and Revision that can be used for
    # # version-based logic.
    #
    # .INPUTS
    # None. You can't pipe objects to Get-PSVersion.
    #
    # .OUTPUTS
    # System.Version. Get-PSVersion returns a [version] value indicating
    # the version of PowerShell that is running.
    #
    # .NOTES
    # Version: 1.0.20251231.0
    #
    # This function is compatible with all versions of PowerShell: Windows
    # PowerShell (v1.0 - 5.1), PowerShell Core 6.x, and PowerShell 7.x and
    # newer. It is compatible with Windows, macOS, and Linux.
    #
    # This function has no parameters.

    param()

    #region License ####################################################
    # Copyright (c) 2025 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining
    # a copy of this software and associated documentation files (the
    # "Software"), to deal in the Software without restriction, including
    # without limitation the rights to use, copy, modify, merge, publish,
    # distribute, sublicense, and/or sell copies of the Software, and to
    # permit persons to whom the Software is furnished to do so, subject to
    # the following conditions:
    #
    # The above copyright notice and this permission notice shall be
    # included in all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
    # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
    # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    # SOFTWARE.
    #endregion License ####################################################

    if (Test-Path variable:\PSVersionTable) {
        return ($PSVersionTable.PSVersion)
    } else {
        return ([version]('1.0'))
    }
}

function Test-Windows {
    # .SYNOPSIS
    # Returns $true if PowerShell is running on Windows; otherwise, returns
    # $false.
    #
    # .DESCRIPTION
    # Returns a boolean ($true or $false) indicating whether the current
    # PowerShell session is running on Windows. This function is useful for
    # writing scripts that need to behave differently on Windows and non-
    # Windows platforms (Linux, macOS, etc.). Additionally, this function is
    # useful because it works on Windows PowerShell 1.0 through 5.1, which do
    # not have the $IsWindows global variable.
    #
    # .PARAMETER PSVersion
    # This parameter is optional; if supplied, it must be the version number of
    # the running version of PowerShell. If the version of PowerShell is
    # already known, it can be passed in to this function to avoid the overhead
    # of unnecessarily determining the version of PowerShell. If this parameter
    # is not supplied, the function will determine the version of PowerShell
    # that is running as part of its processing.
    #
    # .EXAMPLE
    # $boolIsWindows = Test-Windows
    #
    # .EXAMPLE
    # # The version of PowerShell is known to be 2.0 or above:
    # $boolIsWindows = Test-Windows -PSVersion $PSVersionTable.PSVersion
    #
    # .INPUTS
    # None. You can't pipe objects to Test-Windows.
    #
    # .OUTPUTS
    # System.Boolean. Test-Windows returns a boolean value indicating whether
    # PowerShell is running on Windows. $true means that PowerShell is running
    # on Windows; $false means that PowerShell is not running on Windows.
    #
    # .NOTES
    # This function also supports the use of a positional parameter instead of
    # a named parameter. If a positional parameter is used instead of a named
    # parameter, then one positional parameter is required: it must be the
    # version number of the running version of PowerShell. If the version of
    # PowerShell is already known, it can be passed in to this function to
    # avoid the overhead of unnecessarily determining the version of
    # PowerShell. If this parameter is not supplied, the function will
    # determine the version of PowerShell that is running as part of its
    # processing.
    #
    # This function supports Windows PowerShell 1.0 with .NET Framework 2.0 or
    # newer, newer versions of Windows PowerShell (at least up to and including
    # Windows PowerShell 5.1 with .NET Framework 4.8 or newer), PowerShell Core
    # 6.x, and PowerShell 7.x. This function supports Windows, and when run on
    # PowerShell Core 6.x or PowerShell 7.x, also supports macOS and Linux.
    #
    # Version: 1.1.20260109.0

    param (
        [version]$PSVersion = ([version]'0.0')
    )

    #region License ########################################################
    # Copyright (c) 2026 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a
    # copy of this software and associated documentation files (the
    # "Software"), to deal in the Software without restriction, including
    # without limitation the rights to use, copy, modify, merge, publish,
    # distribute, sublicense, and/or sell copies of the Software, and to permit
    # persons to whom the Software is furnished to do so, subject to the
    # following conditions:
    #
    # The above copyright notice and this permission notice shall be included
    # in all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
    # NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    # DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    # OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
    # USE OR OTHER DEALINGS IN THE SOFTWARE.
    #endregion License ########################################################

    function Get-PSVersion {
        # .SYNOPSIS
        # Returns the version of PowerShell that is running.
        #
        # .DESCRIPTION
        # The function outputs a [version] object representing the version of
        # PowerShell that is running. This function detects the PowerShell
        # runtime version but does not detect the underlying .NET Framework or
        # .NET Core version.
        #
        # On versions of PowerShell greater than or equal to version 2.0, this
        # function returns the equivalent of $PSVersionTable.PSVersion
        #
        # PowerShell 1.0 does not have a $PSVersionTable variable, so this
        # function returns [version]('1.0') on PowerShell 1.0.
        #
        # .EXAMPLE
        # $versionPS = Get-PSVersion
        # # $versionPS now contains the version of PowerShell that is running.
        # # On versions of PowerShell greater than or equal to version 2.0,
        # # this function returns the equivalent of $PSVersionTable.PSVersion.
        #
        # .EXAMPLE
        # $versionPS = Get-PSVersion
        # if ($versionPS.Major -ge 2) {
        #     Write-Host "PowerShell 2.0 or later detected"
        # } else {
        #     Write-Host "PowerShell 1.0 detected"
        # }
        # # This example demonstrates storing the returned version object in a
        # # variable and using it to make conditional decisions based on
        # # PowerShell version. The returned [version] object has properties
        # # like Major, Minor, Build, and Revision that can be used for
        # # version-based logic.
        #
        # .INPUTS
        # None. You can't pipe objects to Get-PSVersion.
        #
        # .OUTPUTS
        # System.Version. Get-PSVersion returns a [version] value indicating
        # the version of PowerShell that is running.
        #
        # .NOTES
        # Version: 1.0.20251231.0
        #
        # This function is compatible with all versions of PowerShell: Windows
        # PowerShell (v1.0 - 5.1), PowerShell Core 6.x, and PowerShell 7.x and
        # newer. It is compatible with Windows, macOS, and Linux.
        #
        # This function has no parameters.

        param()

        #region License ####################################################
        # Copyright (c) 2025 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining
        # a copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
        # BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
        # ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
        # CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        # SOFTWARE.
        #endregion License ####################################################

        if (Test-Path variable:\PSVersionTable) {
            return ($PSVersionTable.PSVersion)
        } else {
            return ([version]('1.0'))
        }
    }

    $versionPS = $PSVersion
    if ($null -eq $versionPS -or $versionPS -eq ([version]'0.0')) {
        $versionPS = Get-PSVersion
    }

    if ($versionPS.Major -ge 6) {
        return $IsWindows
    } else {
        return $true
    }
}

function Test-FileWriteability {
    # .SYNOPSIS
    # Tests whether a file path is writable by attempting to create and delete a test
    # file at the specified location.
    #
    # .DESCRIPTION
    # This function verifies whether a caller can write to a target file path by
    # attempting to create/overwrite a file and then delete it. This is used as a
    # preflight check to catch cases like: path invalid or directory missing,
    # insufficient permissions or read-only location, file locked or open in another
    # application, or other IO errors.
    #
    # By default, the function operates silently and returns a boolean value without
    # emitting any errors or warnings. Optional switch parameters can be used to
    # output error or warning messages when the test fails.
    #
    # .PARAMETER Path
    # This parameter is required; it is a string representing the file path to test
    # for writeability. The path can be relative or absolute and will be tested by
    # attempting to create and delete a file at this location.
    #
    # .PARAMETER ReferenceToErrorRecord
    # This parameter is optional; if supplied, it is a reference to an ErrorRecord
    # object. If the test fails, this reference will be populated with the error
    # details from the operation that failed. If the test succeeds, this reference
    # will be set to $null.
    #
    # .PARAMETER WriteErrorOnFailure
    # This parameter is optional; it is a switch parameter. If this parameter is
    # specified, a non-terminating error is written via Write-Error when the file
    # path is not writable. If this parameter is not specified, no error is written.
    #
    # .PARAMETER WriteWarningOnFailure
    # This parameter is optional; it is a switch parameter. If this parameter is
    # specified, a warning is written via Write-Warning when the file path is not
    # writable. If this parameter is not specified, or if the WriteErrorOnFailure
    # parameter was specified, no warning is written.
    #
    # .EXAMPLE
    # $boolIsWritable = Test-FileWriteability -Path 'C:\Temp\test.txt'
    # if ($boolIsWritable) {
    #     Write-Host 'File path is writable'
    # } else {
    #     Write-Host 'File path is not writable'
    # }
    #
    # This example tests whether the path C:\Temp\test.txt is writable. The function
    # returns $true if the path is writable, $false otherwise. No errors or warnings
    # are emitted.
    #
    # .EXAMPLE
    # $boolIsWritable = Test-FileWriteability -Path '.\output.csv' -WriteWarningOnFailure
    # if ($boolIsWritable -eq $false) {
    #     exit 1
    # }
    #
    # This example tests whether the relative path .\output.csv is writable. If the
    # path is not writable, a warning message is displayed. The function returns
    # $false and the script exits with code 1.
    #
    # .EXAMPLE
    # $errRecord = $null
    # $boolIsWritable = Test-FileWriteability -Path 'Z:\InvalidPath\file.log' -ReferenceToErrorRecord ([ref]$errRecord)
    # if ($boolIsWritable -eq $false) {
    #     Write-Host ('Failed to write to path. Error: ' + $errRecord.Exception.Message)
    # }
    #
    # This example tests whether the path Z:\InvalidPath\file.log is writable and
    # captures detailed error information in the $errRecord variable. If the test
    # fails, the error message is displayed.
    #
    # .EXAMPLE
    # $errRef = $null
    # $boolIsWritable = Test-FileWriteability 'C:\Program Files\test.txt' ([ref]$errRef)
    # if ($boolIsWritable -eq $false) {
    #     Write-Host 'Cannot write to Program Files directory'
    # }
    #
    # This example demonstrates using positional parameters instead of named
    # parameters. The first positional parameter is the path, and the second is the
    # reference to error record.
    #
    # .INPUTS
    # None. You can't pipe objects to Test-FileWriteability.
    #
    # .OUTPUTS
    # System.Boolean. Test-FileWriteability returns a boolean value indicating
    # whether the specified file path is writable. $true means the path is writable
    # (file was successfully created and deleted); $false means the path is not
    # writable (creation or deletion failed).
    #
    # .NOTES
    # This function supports Windows PowerShell 1.0 with .NET Framework 2.0 or
    # newer, newer versions of Windows PowerShell (at least up to and including
    # Windows PowerShell 5.1 with .NET Framework 4.8 or newer), PowerShell Core
    # 6.x, and PowerShell 7.x. This function supports Windows and, when run on
    # PowerShell Core 6.x or PowerShell 7.x, also supports macOS and Linux.
    #
    # This function also supports the use of positional parameters instead of named
    # parameters. If positional parameters are used instead of named parameters,
    # then two positional parameters are supported:
    #
    # The first positional parameter is a string representing the file path to test.
    #
    # The second positional parameter is a reference to an ErrorRecord object that
    # will be populated with error details if the test fails.
    #
    # Note: Switch parameters (WriteErrorOnFailure and WriteWarningOnFailure) are
    # not included in positional parameters by default.
    #
    # Version: 1.0.20260313.0

    param (
        [string]$Path = '',
        [ref]$ReferenceToErrorRecord = ([ref]$null),
        [switch]$WriteErrorOnFailure,
        [switch]$WriteWarningOnFailure
    )

    #region License ############################################################
    # Copyright (c) 2026 Frank Lesniak
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy
    # of this software and associated documentation files (the "Software"), to deal
    # in the Software without restriction, including without limitation the rights
    # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    # copies of the Software, and to permit persons to whom the Software is
    # furnished to do so, subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in
    # all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    # SOFTWARE.
    #endregion License ############################################################

    #region HelperFunctions ####################################################
    function New-File {
        # .SYNOPSIS
        # Creates or overwrites a file at the specified path to test write access.
        #
        # .DESCRIPTION
        # This helper function attempts to create or overwrite a file at the
        # specified path. It uses .NET Framework methods to ensure cross-platform
        # compatibility and proper resource cleanup. The function is designed to
        # detect write permission issues, locked files, invalid paths, and other IO
        # errors.
        #
        # .PARAMETER Path
        # This parameter is required; it is a string representing the file path where
        # the file should be created or overwritten.
        #
        # .PARAMETER ReferenceToErrorRecord
        # This parameter is optional; if supplied, it is a reference to an
        # ErrorRecord object. If the file creation fails, this reference will be
        # populated with the error details. If the creation succeeds, this reference
        # will be set to $null.
        #
        # .EXAMPLE
        # $intReturnCode = New-File -Path 'C:\Temp\test.txt'
        # if ($intReturnCode -eq 0) {
        #     Write-Host 'File created successfully'
        # } else {
        #     Write-Host 'File creation failed'
        # }
        #
        # .INPUTS
        # None. You can't pipe objects to New-File.
        #
        # .OUTPUTS
        # System.Int32. New-File returns an integer status code indicating whether
        # the file creation completed successfully. 0 means success. The file was
        # created or overwritten successfully. -1 means failure. An error occurred
        # during the file creation operation.
        #
        # .NOTES
        # This function supports Windows PowerShell 1.0 with .NET Framework 2.0 or
        # newer, newer versions of Windows PowerShell (at least up to and including
        # Windows PowerShell 5.1 with .NET Framework 4.8 or newer), PowerShell Core
        # 6.x, and PowerShell 7.x. This function supports Windows and, when run on
        # PowerShell Core 6.x or PowerShell 7.x, also supports macOS and Linux.
        #
        # This function also supports the use of positional parameters instead of
        # named parameters. If positional parameters are used instead of named
        # parameters, then two positional parameters are required:
        #
        # The first positional parameter is a string representing the file path.
        #
        # The second positional parameter is a reference to an ErrorRecord object.
        #
        # Version: 1.0.20260313.0

        param (
            [string]$Path = '',
            [ref]$ReferenceToErrorRecord = ([ref]$null)
        )

        #region License ########################################################
        # Copyright (c) 2026 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
        # IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
        # CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
        # TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
        # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region FunctionsToSupportErrorHandling ####################################
        function Get-ReferenceToLastError {
            # .SYNOPSIS
            # Gets a reference (memory pointer) to the last error that
            # occurred.
            #
            # .DESCRIPTION
            # Returns a reference (memory pointer) to $null ([ref]$null) if no
            # errors on the $error stack; otherwise, returns a reference to
            # the last error that occurred.
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating
            # # errors from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work:
            # $refLastKnownError = Get-ReferenceToLastError
            #
            # # Store current error preference; we will restore it after we do
            # # some work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will
            # # suppress error output. Terminating errors will not output
            # # anything, kick to the empty trap statement and then continue
            # # on. Likewise, non-terminating errors will also not output
            # # anything, but they do not kick to the trap statement; they
            # # simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # $refNewestCurrentError = Get-ReferenceToLastError
            #
            # $boolErrorOccurred = $false
            # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #     # Both not $null
            #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # } else {
            #     # One is $null, or both are $null
            #     # NOTE: $refLastKnownError could be non-null, while
            #     # $refNewestCurrentError could be null if $error was cleared;
            #     # this does not indicate an error.
            #     #
            #     # So:
            #     # If both are null, no error.
            #     # If $refLastKnownError is null and $refNewestCurrentError is
            #     # non-null, error.
            #     # If $refLastKnownError is non-null and
            #     # $refNewestCurrentError is null, no error.
            #     #
            #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Get-ReferenceToLastError.
            #
            # .OUTPUTS
            # System.Management.Automation.PSReference ([ref]).
            # Get-ReferenceToLastError returns a reference (memory pointer) to
            # the last error that occurred. It returns a reference to $null
            # ([ref]$null) if there are no errors on the $error stack.
            #
            # .NOTES
            # This function accepts no parameters.
            #
            # This function is compatible with Windows PowerShell 1.0+ (with
            # .NET Framework 2.0 or newer), PowerShell Core 6.x, and PowerShell
            # 7.x on Windows, macOS, and Linux.
            #
            # Design Note: This function returns a [ref] object directly rather
            # than following the author's standard v1.0 pattern of returning an
            # integer status code. This design is intentional, as the
            # function's sole purpose is to provide a reference for error
            # tracking. Requiring a [ref] parameter would add unnecessary
            # complexity to the calling pattern.
            #
            # Version: 2.0.20260313.0

            param()

            #region License ################################################
            # Copyright (c) 2025 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person
            # obtaining a copy of this software and associated documentation
            # files (the "Software"), to deal in the Software without
            # restriction, including without limitation the rights to use,
            # copy, modify, merge, publish, distribute, sublicense, and/or sell
            # copies of the Software, and to permit persons to whom the
            # Software is furnished to do so, subject to the following
            # conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
            # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
            # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
            # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
            # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
            # OTHER DEALINGS IN THE SOFTWARE.
            #endregion License ################################################

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return ([ref]$null)
            }
        }

        function Test-ErrorOccurred {
            # .SYNOPSIS
            # Checks to see if an error occurred during a time period, i.e.,
            # during the execution of a command.
            #
            # .DESCRIPTION
            # Using two references (memory pointers) to errors, this function
            # checks to see if an error occurred based on differences between
            # the two errors.
            #
            # To use this function, you must first retrieve a reference to the
            # last error that occurred prior to the command you are about to
            # run. Then, run the command. After the command completes, retrieve
            # a reference to the last error that occurred. Pass these two
            # references to this function to determine if an error occurred.
            #
            # .PARAMETER ReferenceToEarlierError
            # This parameter is required; it is a reference (memory pointer) to
            # a System.Management.Automation.ErrorRecord that represents the
            # newest error on the stack earlier in time, i.e., prior to running
            # the command for which you wish to determine whether an error
            # occurred.
            #
            # If no error was on the stack at this time,
            # ReferenceToEarlierError must be a reference to $null
            # ([ref]$null).
            #
            # .PARAMETER ReferenceToLaterError
            # This parameter is required; it is a reference (memory pointer) to
            # a System.Management.Automation.ErrorRecord that represents the
            # newest error on the stack later in time, i.e., after running
            # the command for which you wish to determine whether an error
            # occurred.
            #
            # If no error was on the stack at this time, ReferenceToLaterError
            # must be a reference to $null ([ref]$null).
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating
            # # errors from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work
            # if ($Error.Count -gt 0) {
            #     $refLastKnownError = ([ref]($Error[0]))
            # } else {
            #     $refLastKnownError = ([ref]$null)
            # }
            #
            # # Store current error preference; we will restore it after we do
            # # some work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will
            # # suppress error output. Terminating errors will not output
            # # anything, kick to the empty trap statement and then continue
            # # on. Likewise, non-terminating errors will also not output
            # # anything, but they do not kick to the trap statement; they
            # # simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # if ($Error.Count -gt 0) {
            #     $refNewestCurrentError = ([ref]($Error[0]))
            # } else {
            #     $refNewestCurrentError = ([ref]$null)
            # }
            #
            # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            #     # Error occurred
            # } else {
            #     # No error occurred
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Test-ErrorOccurred.
            #
            # .OUTPUTS
            # System.Boolean. Test-ErrorOccurred returns a boolean value
            # indicating whether an error occurred during the time period in
            # question. $true indicates an error occurred; $false indicates no
            # error occurred.
            #
            # .NOTES
            # This function also supports the use of positional parameters
            # instead of named parameters. If positional parameters are used
            # instead of named parameters, then two positional parameters are
            # required:
            #
            # The first positional parameter is a reference (memory pointer) to
            # a System.Management.Automation.ErrorRecord that represents the
            # newest error on the stack earlier in time, i.e., prior to running
            # the command for which you wish to determine whether an error
            # occurred. If no error was on the stack at this time, the first
            # positional parameter must be a reference to $null ([ref]$null).
            #
            # The second positional parameter is a reference (memory pointer)
            # to a System.Management.Automation.ErrorRecord that represents the
            # newest error on the stack later in time, i.e., after running
            # the command for which you wish to determine whether an error
            # occurred. If no error was on the stack at this time,
            # ReferenceToLaterError must be a reference to $null ([ref]$null).
            #
            # Version: 2.0.20260313.0

            param (
                [ref]$ReferenceToEarlierError = ([ref]$null),
                [ref]$ReferenceToLaterError = ([ref]$null)
            )

            #region License ################################################
            # Copyright (c) 2025 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person
            # obtaining a copy of this software and associated documentation
            # files (the "Software"), to deal in the Software without
            # restriction, including without limitation the rights to use,
            # copy, modify, merge, publish, distribute, sublicense, and/or sell
            # copies of the Software, and to permit persons to whom the
            # Software is furnished to do so, subject to the following
            # conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
            # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
            # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
            # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
            # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
            # OTHER DEALINGS IN THE SOFTWARE.
            #endregion License ################################################

            $boolErrorOccurred = $false
            if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                # Both not $null
                if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            } else {
                # One is $null, or both are $null
                # NOTE: $ReferenceToEarlierError could be non-null, while
                # $ReferenceToLaterError could be null if $error was cleared;
                # this does not indicate an error.
                # So:
                # - If both are null, no error.
                # - If $ReferenceToEarlierError is null and
                #   $ReferenceToLaterError is non-null, error.
                # - If $ReferenceToEarlierError is non-null and
                #   $ReferenceToLaterError is null, no error.
                if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            }

            return $boolErrorOccurred
        }
        #endregion FunctionsToSupportErrorHandling ####################################

        #region HelperFunctions ####################################################
        function Remove-File {
            # .SYNOPSIS
            # Deletes a file at the specified path.
            #
            # .DESCRIPTION
            # This helper function attempts to delete a file at the specified path. It
            # uses .NET Framework methods to ensure cross-platform compatibility. If the
            # file does not exist, the function treats this as a successful operation (no
            # error). The function is designed to detect permission issues, locked files,
            # and other IO errors.
            #
            # .PARAMETER Path
            # This parameter is required; it is a string representing the file path to
            # delete.
            #
            # .PARAMETER ReferenceToErrorRecord
            # This parameter is optional; if supplied, it is a reference to an
            # ErrorRecord object. If the file deletion fails, this reference will be
            # populated with the error details. If the deletion succeeds, this reference
            # will be set to $null.
            #
            # .EXAMPLE
            # $intReturnCode = Remove-File -Path 'C:\Temp\test.txt'
            # if ($intReturnCode -eq 0) {
            #     Write-Host 'File deleted successfully'
            # } else {
            #     Write-Host 'File deletion failed'
            # }
            #
            # .EXAMPLE
            # $intReturnCode = Remove-File -Path 'C:\Temp\nonexistent.txt'
            # # Returns 0 because the file does not exist (treated as success)
            #
            # .EXAMPLE
            # $errRecord = $null
            # $intReturnCode = Remove-File -Path 'C:\Temp\locked.txt' -ReferenceToErrorRecord ([ref]$errRecord)
            # if ($intReturnCode -ne 0) {
            #     Write-Warning "Failed to delete file: $($errRecord.Exception.Message)"
            # }
            # # Demonstrates capturing error details when deletion fails (e.g., file is locked
            # # or permissions are insufficient)
            #
            # .EXAMPLE
            # $errRecord = $null
            # $intReturnCode = Remove-File 'C:\Temp\test.txt' ([ref]$errRecord)
            # # Demonstrates using positional parameters. First positional parameter is the
            # # file path, second is the reference to error record.
            #
            # .INPUTS
            # None. You can't pipe objects to Remove-File.
            #
            # .OUTPUTS
            # System.Int32. Remove-File returns an integer status code indicating whether
            # the file deletion completed successfully. 0 means success. The file was
            # deleted successfully, or the file did not exist. -1 means failure. An error
            # occurred during the file deletion operation.
            #
            # .NOTES
            # This function supports Windows PowerShell 1.0 with .NET Framework 2.0 or
            # newer, newer versions of Windows PowerShell (at least up to and including
            # Windows PowerShell 5.1 with .NET Framework 4.8 or newer), PowerShell Core
            # 6.x, and PowerShell 7.x. This function supports Windows and, when run on
            # PowerShell Core 6.x or PowerShell 7.x, also supports macOS and Linux.
            #
            # This function also supports the use of positional parameters instead of
            # named parameters. If positional parameters are used instead of named
            # parameters, then two positional parameters are required:
            #
            # The first positional parameter is a string representing the file path.
            #
            # The second positional parameter is a reference to an ErrorRecord object.
            #
            # Version: 1.0.20260313.0

            param (
                [string]$Path,
                [ref]$ReferenceToErrorRecord = ([ref]$null)
            )

            #region License ########################################################
            # Copyright (c) 2026 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining a
            # copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be included
            # in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
            # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
            # IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
            # CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
            # TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
            # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
            #endregion License ########################################################

            #region FunctionsToSupportErrorHandling ####################################
            function Get-ReferenceToLastError {
                # .SYNOPSIS
                # Gets a reference (memory pointer) to the last error that
                # occurred.
                #
                # .DESCRIPTION
                # Returns a reference (memory pointer) to $null ([ref]$null) if no
                # errors on the $error stack; otherwise, returns a reference to
                # the last error that occurred.
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating
                # # errors from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work:
                # $refLastKnownError = Get-ReferenceToLastError
                #
                # # Store current error preference; we will restore it after we do
                # # some work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will
                # # suppress error output. Terminating errors will not output
                # # anything, kick to the empty trap statement and then continue
                # # on. Likewise, non-terminating errors will also not output
                # # anything, but they do not kick to the trap statement; they
                # # simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # $refNewestCurrentError = Get-ReferenceToLastError
                #
                # $boolErrorOccurred = $false
                # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #     # Both not $null
                #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # } else {
                #     # One is $null, or both are $null
                #     # NOTE: $refLastKnownError could be non-null, while
                #     # $refNewestCurrentError could be null if $error was cleared;
                #     # this does not indicate an error.
                #     #
                #     # So:
                #     # If both are null, no error.
                #     # If $refLastKnownError is null and $refNewestCurrentError is
                #     # non-null, error.
                #     # If $refLastKnownError is non-null and
                #     # $refNewestCurrentError is null, no error.
                #     #
                #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Get-ReferenceToLastError.
                #
                # .OUTPUTS
                # System.Management.Automation.PSReference ([ref]).
                # Get-ReferenceToLastError returns a reference (memory pointer) to
                # the last error that occurred. It returns a reference to $null
                # ([ref]$null) if there are no errors on the $error stack.
                #
                # .NOTES
                # This function accepts no parameters.
                #
                # This function is compatible with Windows PowerShell 1.0+ (with
                # .NET Framework 2.0 or newer), PowerShell Core 6.x, and PowerShell
                # 7.x on Windows, macOS, and Linux.
                #
                # Design Note: This function returns a [ref] object directly rather
                # than following the author's standard v1.0 pattern of returning an
                # integer status code. This design is intentional, as the
                # function's sole purpose is to provide a reference for error
                # tracking. Requiring a [ref] parameter would add unnecessary
                # complexity to the calling pattern.
                #
                # Version: 2.0.20260313.0

                param()

                #region License ################################################
                # Copyright (c) 2025 Frank Lesniak
                #
                # Permission is hereby granted, free of charge, to any person
                # obtaining a copy of this software and associated documentation
                # files (the "Software"), to deal in the Software without
                # restriction, including without limitation the rights to use,
                # copy, modify, merge, publish, distribute, sublicense, and/or sell
                # copies of the Software, and to permit persons to whom the
                # Software is furnished to do so, subject to the following
                # conditions:
                #
                # The above copyright notice and this permission notice shall be
                # included in all copies or substantial portions of the Software.
                #
                # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
                # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
                # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
                # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
                # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
                # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
                # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
                # OTHER DEALINGS IN THE SOFTWARE.
                #endregion License ################################################

                if ($Error.Count -gt 0) {
                    return ([ref]($Error[0]))
                } else {
                    return ([ref]$null)
                }
            }

            function Test-ErrorOccurred {
                # .SYNOPSIS
                # Checks to see if an error occurred during a time period, i.e.,
                # during the execution of a command.
                #
                # .DESCRIPTION
                # Using two references (memory pointers) to errors, this function
                # checks to see if an error occurred based on differences between
                # the two errors.
                #
                # To use this function, you must first retrieve a reference to the
                # last error that occurred prior to the command you are about to
                # run. Then, run the command. After the command completes, retrieve
                # a reference to the last error that occurred. Pass these two
                # references to this function to determine if an error occurred.
                #
                # .PARAMETER ReferenceToEarlierError
                # This parameter is required; it is a reference (memory pointer) to
                # a System.Management.Automation.ErrorRecord that represents the
                # newest error on the stack earlier in time, i.e., prior to running
                # the command for which you wish to determine whether an error
                # occurred.
                #
                # If no error was on the stack at this time,
                # ReferenceToEarlierError must be a reference to $null
                # ([ref]$null).
                #
                # .PARAMETER ReferenceToLaterError
                # This parameter is required; it is a reference (memory pointer) to
                # a System.Management.Automation.ErrorRecord that represents the
                # newest error on the stack later in time, i.e., after running
                # the command for which you wish to determine whether an error
                # occurred.
                #
                # If no error was on the stack at this time, ReferenceToLaterError
                # must be a reference to $null ([ref]$null).
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating
                # # errors from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work
                # if ($Error.Count -gt 0) {
                #     $refLastKnownError = ([ref]($Error[0]))
                # } else {
                #     $refLastKnownError = ([ref]$null)
                # }
                #
                # # Store current error preference; we will restore it after we do
                # # some work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will
                # # suppress error output. Terminating errors will not output
                # # anything, kick to the empty trap statement and then continue
                # # on. Likewise, non-terminating errors will also not output
                # # anything, but they do not kick to the trap statement; they
                # # simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # if ($Error.Count -gt 0) {
                #     $refNewestCurrentError = ([ref]($Error[0]))
                # } else {
                #     $refNewestCurrentError = ([ref]$null)
                # }
                #
                # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                #     # Error occurred
                # } else {
                #     # No error occurred
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Test-ErrorOccurred.
                #
                # .OUTPUTS
                # System.Boolean. Test-ErrorOccurred returns a boolean value
                # indicating whether an error occurred during the time period in
                # question. $true indicates an error occurred; $false indicates no
                # error occurred.
                #
                # .NOTES
                # This function also supports the use of positional parameters
                # instead of named parameters. If positional parameters are used
                # instead of named parameters, then two positional parameters are
                # required:
                #
                # The first positional parameter is a reference (memory pointer) to
                # a System.Management.Automation.ErrorRecord that represents the
                # newest error on the stack earlier in time, i.e., prior to running
                # the command for which you wish to determine whether an error
                # occurred. If no error was on the stack at this time, the first
                # positional parameter must be a reference to $null ([ref]$null).
                #
                # The second positional parameter is a reference (memory pointer)
                # to a System.Management.Automation.ErrorRecord that represents the
                # newest error on the stack later in time, i.e., after running
                # the command for which you wish to determine whether an error
                # occurred. If no error was on the stack at this time,
                # ReferenceToLaterError must be a reference to $null ([ref]$null).
                #
                # Version: 2.0.20260313.0

                param (
                    [ref]$ReferenceToEarlierError = ([ref]$null),
                    [ref]$ReferenceToLaterError = ([ref]$null)
                )

                #region License ################################################
                # Copyright (c) 2025 Frank Lesniak
                #
                # Permission is hereby granted, free of charge, to any person
                # obtaining a copy of this software and associated documentation
                # files (the "Software"), to deal in the Software without
                # restriction, including without limitation the rights to use,
                # copy, modify, merge, publish, distribute, sublicense, and/or sell
                # copies of the Software, and to permit persons to whom the
                # Software is furnished to do so, subject to the following
                # conditions:
                #
                # The above copyright notice and this permission notice shall be
                # included in all copies or substantial portions of the Software.
                #
                # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
                # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
                # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
                # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
                # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
                # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
                # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
                # OTHER DEALINGS IN THE SOFTWARE.
                #endregion License ################################################

                $boolErrorOccurred = $false
                if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    # Both not $null
                    if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                        $boolErrorOccurred = $true
                    }
                } else {
                    # One is $null, or both are $null
                    # NOTE: $ReferenceToEarlierError could be non-null, while
                    # $ReferenceToLaterError could be null if $error was cleared;
                    # this does not indicate an error.
                    # So:
                    # - If both are null, no error.
                    # - If $ReferenceToEarlierError is null and
                    #   $ReferenceToLaterError is non-null, error.
                    # - If $ReferenceToEarlierError is non-null and
                    #   $ReferenceToLaterError is null, no error.
                    if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                        $boolErrorOccurred = $true
                    }
                }

                return $boolErrorOccurred
            }
            #endregion FunctionsToSupportErrorHandling ####################################

            #region HelperFunctions ####################################################
            function Test-FileExistence {
                # .SYNOPSIS
                # Tests whether a file exists at the specified path.
                #
                # .DESCRIPTION
                # This helper function checks whether a file exists at the specified path using
                # .NET Framework methods to ensure cross-platform compatibility. The function
                # returns a boolean value indicating the file's existence. If an error occurs
                # during the check, the function returns $false.
                #
                # .PARAMETER Path
                # This parameter is required; it is a string representing the file path to
                # test.
                #
                # .EXAMPLE
                # $boolExists = Test-FileExistence -Path 'C:\Temp\test.txt'
                # if ($boolExists) {
                #     Write-Host 'File exists'
                # } else {
                #     Write-Host 'File does not exist'
                # }
                #
                # .EXAMPLE
                # $boolExists = Test-FileExistence 'C:\Temp\test.txt'
                # # Demonstrates using positional parameters. The positional parameter is the
                # # file path.
                #
                # .INPUTS
                # None. You can't pipe objects to Test-FileExistence.
                #
                # .OUTPUTS
                # System.Boolean. Test-FileExistence returns a boolean value indicating whether
                # the file exists. $true means the file exists. $false means the file does not
                # exist or an error occurred during the check.
                #
                # .NOTES
                # This function supports Windows PowerShell 1.0 with .NET Framework 2.0 or
                # newer, newer versions of Windows PowerShell (at least up to and including
                # Windows PowerShell 5.1 with .NET Framework 4.8 or newer), PowerShell Core
                # 6.x, and PowerShell 7.x. This function supports Windows and, when run on
                # PowerShell Core 6.x or PowerShell 7.x, also supports macOS and Linux.
                #
                # This function also supports the use of positional parameters instead of
                # named parameters. If positional parameters are used instead of named
                # parameters, then one positional parameter is required:
                #
                # The first positional parameter is a string representing the file path.
                #
                # Version: 1.0.20260313.0

                param (
                    [string]$Path
                )

                #region License ########################################################
                # Copyright (c) 2026 Frank Lesniak
                #
                # Permission is hereby granted, free of charge, to any person obtaining a
                # copy of this software and associated documentation files (the
                # "Software"), to deal in the Software without restriction, including
                # without limitation the rights to use, copy, modify, merge, publish,
                # distribute, sublicense, and/or sell copies of the Software, and to
                # permit persons to whom the Software is furnished to do so, subject to
                # the following conditions:
                #
                # The above copyright notice and this permission notice shall be included
                # in all copies or substantial portions of the Software.
                #
                # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
                # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
                # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
                # IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
                # CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
                # TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
                # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
                #endregion License ########################################################

                #region FunctionsToSupportErrorHandling ####################################
                function Get-ReferenceToLastError {
                    # .SYNOPSIS
                    # Gets a reference (memory pointer) to the last error that
                    # occurred.
                    #
                    # .DESCRIPTION
                    # Returns a reference (memory pointer) to $null ([ref]$null) if no
                    # errors on the $error stack; otherwise, returns a reference to
                    # the last error that occurred.
                    #
                    # .EXAMPLE
                    # # Intentionally empty trap statement to prevent terminating
                    # # errors from halting processing
                    # trap { }
                    #
                    # # Retrieve the newest error on the stack prior to doing work:
                    # $refLastKnownError = Get-ReferenceToLastError
                    #
                    # # Store current error preference; we will restore it after we do
                    # # some work:
                    # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                    #
                    # # Set ErrorActionPreference to SilentlyContinue; this will
                    # # suppress error output. Terminating errors will not output
                    # # anything, kick to the empty trap statement and then continue
                    # # on. Likewise, non-terminating errors will also not output
                    # # anything, but they do not kick to the trap statement; they
                    # # simply continue on.
                    # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                    #
                    # # Do something that might trigger an error
                    # Get-Item -Path 'C:\MayNotExist.txt'
                    #
                    # # Restore the former error preference
                    # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                    #
                    # # Retrieve the newest error on the error stack
                    # $refNewestCurrentError = Get-ReferenceToLastError
                    #
                    # $boolErrorOccurred = $false
                    # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                    #     # Both not $null
                    #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
                    #         $boolErrorOccurred = $true
                    #     }
                    # } else {
                    #     # One is $null, or both are $null
                    #     # NOTE: $refLastKnownError could be non-null, while
                    #     # $refNewestCurrentError could be null if $error was cleared;
                    #     # this does not indicate an error.
                    #     #
                    #     # So:
                    #     # If both are null, no error.
                    #     # If $refLastKnownError is null and $refNewestCurrentError is
                    #     # non-null, error.
                    #     # If $refLastKnownError is non-null and
                    #     # $refNewestCurrentError is null, no error.
                    #     #
                    #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                    #         $boolErrorOccurred = $true
                    #     }
                    # }
                    #
                    # .INPUTS
                    # None. You can't pipe objects to Get-ReferenceToLastError.
                    #
                    # .OUTPUTS
                    # System.Management.Automation.PSReference ([ref]).
                    # Get-ReferenceToLastError returns a reference (memory pointer) to
                    # the last error that occurred. It returns a reference to $null
                    # ([ref]$null) if there are no errors on the $error stack.
                    #
                    # .NOTES
                    # This function accepts no parameters.
                    #
                    # This function is compatible with Windows PowerShell 1.0+ (with
                    # .NET Framework 2.0 or newer), PowerShell Core 6.x, and PowerShell
                    # 7.x on Windows, macOS, and Linux.
                    #
                    # Design Note: This function returns a [ref] object directly rather
                    # than following the author's standard v1.0 pattern of returning an
                    # integer status code. This design is intentional, as the
                    # function's sole purpose is to provide a reference for error
                    # tracking. Requiring a [ref] parameter would add unnecessary
                    # complexity to the calling pattern.
                    #
                    # Version: 2.0.20260313.0

                    param()

                    #region License ################################################
                    # Copyright (c) 2025 Frank Lesniak
                    #
                    # Permission is hereby granted, free of charge, to any person
                    # obtaining a copy of this software and associated documentation
                    # files (the "Software"), to deal in the Software without
                    # restriction, including without limitation the rights to use,
                    # copy, modify, merge, publish, distribute, sublicense, and/or sell
                    # copies of the Software, and to permit persons to whom the
                    # Software is furnished to do so, subject to the following
                    # conditions:
                    #
                    # The above copyright notice and this permission notice shall be
                    # included in all copies or substantial portions of the Software.
                    #
                    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
                    # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
                    # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
                    # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
                    # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
                    # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
                    # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
                    # OTHER DEALINGS IN THE SOFTWARE.
                    #endregion License ################################################

                    if ($Error.Count -gt 0) {
                        return ([ref]($Error[0]))
                    } else {
                        return ([ref]$null)
                    }
                }

                function Test-ErrorOccurred {
                    # .SYNOPSIS
                    # Checks to see if an error occurred during a time period, i.e.,
                    # during the execution of a command.
                    #
                    # .DESCRIPTION
                    # Using two references (memory pointers) to errors, this function
                    # checks to see if an error occurred based on differences between
                    # the two errors.
                    #
                    # To use this function, you must first retrieve a reference to the
                    # last error that occurred prior to the command you are about to
                    # run. Then, run the command. After the command completes, retrieve
                    # a reference to the last error that occurred. Pass these two
                    # references to this function to determine if an error occurred.
                    #
                    # .PARAMETER ReferenceToEarlierError
                    # This parameter is required; it is a reference (memory pointer) to
                    # a System.Management.Automation.ErrorRecord that represents the
                    # newest error on the stack earlier in time, i.e., prior to running
                    # the command for which you wish to determine whether an error
                    # occurred.
                    #
                    # If no error was on the stack at this time,
                    # ReferenceToEarlierError must be a reference to $null
                    # ([ref]$null).
                    #
                    # .PARAMETER ReferenceToLaterError
                    # This parameter is required; it is a reference (memory pointer) to
                    # a System.Management.Automation.ErrorRecord that represents the
                    # newest error on the stack later in time, i.e., after running
                    # the command for which you wish to determine whether an error
                    # occurred.
                    #
                    # If no error was on the stack at this time, ReferenceToLaterError
                    # must be a reference to $null ([ref]$null).
                    #
                    # .EXAMPLE
                    # # Intentionally empty trap statement to prevent terminating
                    # # errors from halting processing
                    # trap { }
                    #
                    # # Retrieve the newest error on the stack prior to doing work
                    # if ($Error.Count -gt 0) {
                    #     $refLastKnownError = ([ref]($Error[0]))
                    # } else {
                    #     $refLastKnownError = ([ref]$null)
                    # }
                    #
                    # # Store current error preference; we will restore it after we do
                    # # some work:
                    # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                    #
                    # # Set ErrorActionPreference to SilentlyContinue; this will
                    # # suppress error output. Terminating errors will not output
                    # # anything, kick to the empty trap statement and then continue
                    # # on. Likewise, non-terminating errors will also not output
                    # # anything, but they do not kick to the trap statement; they
                    # # simply continue on.
                    # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                    #
                    # # Do something that might trigger an error
                    # Get-Item -Path 'C:\MayNotExist.txt'
                    #
                    # # Restore the former error preference
                    # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                    #
                    # # Retrieve the newest error on the error stack
                    # if ($Error.Count -gt 0) {
                    #     $refNewestCurrentError = ([ref]($Error[0]))
                    # } else {
                    #     $refNewestCurrentError = ([ref]$null)
                    # }
                    #
                    # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                    #     # Error occurred
                    # } else {
                    #     # No error occurred
                    # }
                    #
                    # .INPUTS
                    # None. You can't pipe objects to Test-ErrorOccurred.
                    #
                    # .OUTPUTS
                    # System.Boolean. Test-ErrorOccurred returns a boolean value
                    # indicating whether an error occurred during the time period in
                    # question. $true indicates an error occurred; $false indicates no
                    # error occurred.
                    #
                    # .NOTES
                    # This function supports Windows PowerShell 1.0 with .NET Framework
                    # 2.0 or newer, newer versions of Windows PowerShell (at least up
                    # to and including Windows PowerShell 5.1 with .NET Framework 4.8
                    # or newer), PowerShell Core 6.x, and PowerShell 7.x. This function
                    # supports Windows and, when run on PowerShell Core 6.x or
                    # PowerShell 7.x, also supports macOS and Linux.
                    #
                    # This function also supports the use of positional parameters
                    # instead of named parameters. If positional parameters are used
                    # instead of named parameters, then two positional parameters are
                    # required:
                    #
                    # The first positional parameter is a reference (memory pointer) to
                    # a System.Management.Automation.ErrorRecord that represents the
                    # newest error on the stack earlier in time, i.e., prior to running
                    # the command for which you wish to determine whether an error
                    # occurred. If no error was on the stack at this time, the first
                    # positional parameter must be a reference to $null ([ref]$null).
                    #
                    # The second positional parameter is a reference (memory pointer)
                    # to a System.Management.Automation.ErrorRecord that represents the
                    # newest error on the stack later in time, i.e., after running
                    # the command for which you wish to determine whether an error
                    # occurred. If no error was on the stack at this time,
                    # ReferenceToLaterError must be a reference to $null ([ref]$null).
                    #
                    # Version: 2.0.20260313.0

                    param (
                        [ref]$ReferenceToEarlierError = ([ref]$null),
                        [ref]$ReferenceToLaterError = ([ref]$null)
                    )

                    #region License ################################################
                    # Copyright (c) 2025 Frank Lesniak
                    #
                    # Permission is hereby granted, free of charge, to any person
                    # obtaining a copy of this software and associated documentation
                    # files (the "Software"), to deal in the Software without
                    # restriction, including without limitation the rights to use,
                    # copy, modify, merge, publish, distribute, sublicense, and/or sell
                    # copies of the Software, and to permit persons to whom the
                    # Software is furnished to do so, subject to the following
                    # conditions:
                    #
                    # The above copyright notice and this permission notice shall be
                    # included in all copies or substantial portions of the Software.
                    #
                    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
                    # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
                    # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
                    # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
                    # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
                    # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
                    # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
                    # OTHER DEALINGS IN THE SOFTWARE.
                    #endregion License ################################################

                    $boolErrorOccurred = $false
                    if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                        # Both not $null
                        if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                            $boolErrorOccurred = $true
                        }
                    } else {
                        # One is $null, or both are $null
                        # NOTE: $ReferenceToEarlierError could be non-null, while
                        # $ReferenceToLaterError could be null if $error was cleared;
                        # this does not indicate an error.
                        # So:
                        # - If both are null, no error.
                        # - If $ReferenceToEarlierError is null and
                        #   $ReferenceToLaterError is non-null, error.
                        # - If $ReferenceToEarlierError is non-null and
                        #   $ReferenceToLaterError is null, no error.
                        if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                            $boolErrorOccurred = $true
                        }
                    }

                    return $boolErrorOccurred
                }
                #endregion FunctionsToSupportErrorHandling ####################################

                trap {
                    # Intentionally left empty to prevent terminating errors from halting
                    # processing
                }

                # Validate input
                if ([string]::IsNullOrEmpty($Path)) {
                    return $false
                }

                # Retrieve the newest error on the stack prior to doing work
                $refLastKnownError = Get-ReferenceToLastError

                # Store current error preference; we will restore it after we do the work of
                # this function
                $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

                # Set ErrorActionPreference to SilentlyContinue; this will suppress error
                # output. Terminating errors will not output anything, kick to the empty trap
                # statement and then continue on. Likewise, non-terminating errors will also
                # not output anything, but they do not kick to the trap statement; they simply
                # continue on.
                $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

                # Check if file exists using .NET method
                $boolFileExists = [System.IO.File]::Exists($Path)

                # Restore the former error preference
                $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

                # Retrieve the newest error on the error stack
                $refNewestCurrentError = Get-ReferenceToLastError

                if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                    # Error occurred
                    return $false
                } else {
                    # No error occurred
                    return $boolFileExists
                }
            }
            #endregion HelperFunctions ####################################################

            trap {
                # Intentionally left empty to prevent terminating errors from halting
                # processing
            }

            # Validate input
            if ([string]::IsNullOrEmpty($Path)) {
                return -1
            }

            # Check if file exists before attempting deletion
            $boolFileExists = Test-FileExistence -Path $Path

            if ($boolFileExists -eq $false) {
                # File does not exist; treat as success
                $ReferenceToErrorRecord.Value = $null
                return 0
            }

            # File exists; attempt to delete it
            # Retrieve the newest error on the stack prior to doing work
            $refLastKnownError = Get-ReferenceToLastError

            # Store current error preference
            $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

            # Set ErrorActionPreference to SilentlyContinue
            $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

            # Attempt to delete the file using .NET method
            [System.IO.File]::Delete($Path)

            # Restore the former error preference
            $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

            # Retrieve the newest error on the error stack
            $refNewestCurrentError = Get-ReferenceToLastError

            if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
                # Error occurred
                $ReferenceToErrorRecord.Value = $refNewestCurrentError.Value
                return -1
            } else {
                # No error occurred
                $ReferenceToErrorRecord.Value = $null
                return 0
            }
        }
        #endregion HelperFunctions ####################################################

        trap {
            # Intentionally left empty to prevent terminating errors from halting
            # processing
        }

        # Validate input
        if ([string]::IsNullOrEmpty($Path)) {
            return -1
        }

        # Retrieve the newest error on the stack prior to doing work
        $refLastKnownError = Get-ReferenceToLastError

        # Store current error preference; we will restore it after we do the work
        $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

        # Set ErrorActionPreference to SilentlyContinue; this will suppress error
        # output. Terminating errors will not output anything, kick to the empty
        # trap statement and then continue on. Likewise, non-terminating errors
        # will also not output anything, but they do not kick to the trap
        # statement; they simply continue on.
        $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

        # Attempt to create the file using .NET FileStream with FileMode.Create
        # This will overwrite the file if it exists, or create it if it doesn't
        $objFileStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
            # Error occurred during file creation
            $ReferenceToErrorRecord.Value = $refNewestCurrentError.Value

            if ($null -ne $objFileStream) {
                # If the FileStream object was partially created, attempt cleanup

                # Retrieve the newest error on the stack prior to closing the file stream
                $refLastKnownError = Get-ReferenceToLastError

                # Store current error preference
                $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

                # Set ErrorActionPreference to SilentlyContinue
                $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

                # Close and dispose of the file stream
                $objFileStream.Close(); $objFileStream.Dispose()

                # Restore the former error preference
                $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

                # Retrieve the newest error on the error stack
                $refNewestCurrentError = Get-ReferenceToLastError

                if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
                    # Error occurred during file stream closure; write to debug stream
                    # This is a non-critical error as the file was already created successfully
                    Write-Debug ("Failed to close file stream cleanly: {0}" -f ($refNewestCurrentError.Value.Exception.Message))
                }
            }

            # Best-effort cleanup: if a partial file was created, try to remove it
            # using Remove-File helper function
            $refDummyError = $null
            [void](Remove-File -Path $Path -ReferenceToErrorRecord ([ref]$refDummyError))

            return -1
        } else {
            # No error occurred; close the file stream
            if ($null -ne $objFileStream) {
                # Retrieve the newest error on the stack prior to closing the file stream
                $refLastKnownError = Get-ReferenceToLastError

                # Store current error preference
                $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

                # Set ErrorActionPreference to SilentlyContinue
                $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

                # Close and dispose of the file stream
                $objFileStream.Close(); $objFileStream.Dispose()

                # Restore the former error preference
                $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

                # Retrieve the newest error on the error stack
                $refNewestCurrentError = Get-ReferenceToLastError

                if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
                    # Error occurred during file stream closure; write to debug stream
                    # This is a non-critical error as the file was already created successfully
                    Write-Debug ("Failed to close file stream cleanly: {0}" -f ($refNewestCurrentError.Value.Exception.Message))
                }
            }

            # Clear error record reference if provided
            $ReferenceToErrorRecord.Value = $null

            return 0
        }
    }

    function Remove-File {
        # .SYNOPSIS
        # Deletes a file at the specified path.
        #
        # .DESCRIPTION
        # This helper function attempts to delete a file at the specified path. It
        # uses .NET Framework methods to ensure cross-platform compatibility. If the
        # file does not exist, the function treats this as a successful operation (no
        # error). The function is designed to detect permission issues, locked files,
        # and other IO errors.
        #
        # .PARAMETER Path
        # This parameter is required; it is a string representing the file path to
        # delete.
        #
        # .PARAMETER ReferenceToErrorRecord
        # This parameter is optional; if supplied, it is a reference to an
        # ErrorRecord object. If the file deletion fails, this reference will be
        # populated with the error details. If the deletion succeeds, this reference
        # will be set to $null.
        #
        # .EXAMPLE
        # $intReturnCode = Remove-File -Path 'C:\Temp\test.txt'
        # if ($intReturnCode -eq 0) {
        #     Write-Host 'File deleted successfully'
        # } else {
        #     Write-Host 'File deletion failed'
        # }
        #
        # .EXAMPLE
        # $intReturnCode = Remove-File -Path 'C:\Temp\nonexistent.txt'
        # # Returns 0 because the file does not exist (treated as success)
        #
        # .EXAMPLE
        # $errRecord = $null
        # $intReturnCode = Remove-File -Path 'C:\Temp\locked.txt' -ReferenceToErrorRecord ([ref]$errRecord)
        # if ($intReturnCode -ne 0) {
        #     Write-Warning "Failed to delete file: $($errRecord.Exception.Message)"
        # }
        # # Demonstrates capturing error details when deletion fails (e.g., file is locked
        # # or permissions are insufficient)
        #
        # .EXAMPLE
        # $errRecord = $null
        # $intReturnCode = Remove-File 'C:\Temp\test.txt' ([ref]$errRecord)
        # # Demonstrates using positional parameters. First positional parameter is the
        # # file path, second is the reference to error record.
        #
        # .INPUTS
        # None. You can't pipe objects to Remove-File.
        #
        # .OUTPUTS
        # System.Int32. Remove-File returns an integer status code indicating whether
        # the file deletion completed successfully. 0 means success. The file was
        # deleted successfully, or the file did not exist. -1 means failure. An error
        # occurred during the file deletion operation.
        #
        # .NOTES
        # This function supports Windows PowerShell 1.0 with .NET Framework 2.0 or
        # newer, newer versions of Windows PowerShell (at least up to and including
        # Windows PowerShell 5.1 with .NET Framework 4.8 or newer), PowerShell Core
        # 6.x, and PowerShell 7.x. This function supports Windows and, when run on
        # PowerShell Core 6.x or PowerShell 7.x, also supports macOS and Linux.
        #
        # This function also supports the use of positional parameters instead of
        # named parameters. If positional parameters are used instead of named
        # parameters, then two positional parameters are required:
        #
        # The first positional parameter is a string representing the file path.
        #
        # The second positional parameter is a reference to an ErrorRecord object.
        #
        # Version: 1.0.20260313.0

        param (
            [string]$Path,
            [ref]$ReferenceToErrorRecord = ([ref]$null)
        )

        #region License ########################################################
        # Copyright (c) 2026 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person obtaining a
        # copy of this software and associated documentation files (the
        # "Software"), to deal in the Software without restriction, including
        # without limitation the rights to use, copy, modify, merge, publish,
        # distribute, sublicense, and/or sell copies of the Software, and to
        # permit persons to whom the Software is furnished to do so, subject to
        # the following conditions:
        #
        # The above copyright notice and this permission notice shall be included
        # in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
        # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
        # IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
        # CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
        # TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
        # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ########################################################

        #region FunctionsToSupportErrorHandling ####################################
        function Get-ReferenceToLastError {
            # .SYNOPSIS
            # Gets a reference (memory pointer) to the last error that
            # occurred.
            #
            # .DESCRIPTION
            # Returns a reference (memory pointer) to $null ([ref]$null) if no
            # errors on the $error stack; otherwise, returns a reference to
            # the last error that occurred.
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating
            # # errors from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work:
            # $refLastKnownError = Get-ReferenceToLastError
            #
            # # Store current error preference; we will restore it after we do
            # # some work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will
            # # suppress error output. Terminating errors will not output
            # # anything, kick to the empty trap statement and then continue
            # # on. Likewise, non-terminating errors will also not output
            # # anything, but they do not kick to the trap statement; they
            # # simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # $refNewestCurrentError = Get-ReferenceToLastError
            #
            # $boolErrorOccurred = $false
            # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #     # Both not $null
            #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # } else {
            #     # One is $null, or both are $null
            #     # NOTE: $refLastKnownError could be non-null, while
            #     # $refNewestCurrentError could be null if $error was cleared;
            #     # this does not indicate an error.
            #     #
            #     # So:
            #     # If both are null, no error.
            #     # If $refLastKnownError is null and $refNewestCurrentError is
            #     # non-null, error.
            #     # If $refLastKnownError is non-null and
            #     # $refNewestCurrentError is null, no error.
            #     #
            #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
            #         $boolErrorOccurred = $true
            #     }
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Get-ReferenceToLastError.
            #
            # .OUTPUTS
            # System.Management.Automation.PSReference ([ref]).
            # Get-ReferenceToLastError returns a reference (memory pointer) to
            # the last error that occurred. It returns a reference to $null
            # ([ref]$null) if there are no errors on the $error stack.
            #
            # .NOTES
            # This function accepts no parameters.
            #
            # This function is compatible with Windows PowerShell 1.0+ (with
            # .NET Framework 2.0 or newer), PowerShell Core 6.x, and PowerShell
            # 7.x on Windows, macOS, and Linux.
            #
            # Design Note: This function returns a [ref] object directly rather
            # than following the author's standard v1.0 pattern of returning an
            # integer status code. This design is intentional, as the
            # function's sole purpose is to provide a reference for error
            # tracking. Requiring a [ref] parameter would add unnecessary
            # complexity to the calling pattern.
            #
            # Version: 2.0.20260313.0

            param()

            #region License ################################################
            # Copyright (c) 2025 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person
            # obtaining a copy of this software and associated documentation
            # files (the "Software"), to deal in the Software without
            # restriction, including without limitation the rights to use,
            # copy, modify, merge, publish, distribute, sublicense, and/or sell
            # copies of the Software, and to permit persons to whom the
            # Software is furnished to do so, subject to the following
            # conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
            # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
            # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
            # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
            # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
            # OTHER DEALINGS IN THE SOFTWARE.
            #endregion License ################################################

            if ($Error.Count -gt 0) {
                return ([ref]($Error[0]))
            } else {
                return ([ref]$null)
            }
        }

        function Test-ErrorOccurred {
            # .SYNOPSIS
            # Checks to see if an error occurred during a time period, i.e.,
            # during the execution of a command.
            #
            # .DESCRIPTION
            # Using two references (memory pointers) to errors, this function
            # checks to see if an error occurred based on differences between
            # the two errors.
            #
            # To use this function, you must first retrieve a reference to the
            # last error that occurred prior to the command you are about to
            # run. Then, run the command. After the command completes, retrieve
            # a reference to the last error that occurred. Pass these two
            # references to this function to determine if an error occurred.
            #
            # .PARAMETER ReferenceToEarlierError
            # This parameter is required; it is a reference (memory pointer) to
            # a System.Management.Automation.ErrorRecord that represents the
            # newest error on the stack earlier in time, i.e., prior to running
            # the command for which you wish to determine whether an error
            # occurred.
            #
            # If no error was on the stack at this time,
            # ReferenceToEarlierError must be a reference to $null
            # ([ref]$null).
            #
            # .PARAMETER ReferenceToLaterError
            # This parameter is required; it is a reference (memory pointer) to
            # a System.Management.Automation.ErrorRecord that represents the
            # newest error on the stack later in time, i.e., after running
            # the command for which you wish to determine whether an error
            # occurred.
            #
            # If no error was on the stack at this time, ReferenceToLaterError
            # must be a reference to $null ([ref]$null).
            #
            # .EXAMPLE
            # # Intentionally empty trap statement to prevent terminating
            # # errors from halting processing
            # trap { }
            #
            # # Retrieve the newest error on the stack prior to doing work
            # if ($Error.Count -gt 0) {
            #     $refLastKnownError = ([ref]($Error[0]))
            # } else {
            #     $refLastKnownError = ([ref]$null)
            # }
            #
            # # Store current error preference; we will restore it after we do
            # # some work:
            # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
            #
            # # Set ErrorActionPreference to SilentlyContinue; this will
            # # suppress error output. Terminating errors will not output
            # # anything, kick to the empty trap statement and then continue
            # # on. Likewise, non-terminating errors will also not output
            # # anything, but they do not kick to the trap statement; they
            # # simply continue on.
            # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            #
            # # Do something that might trigger an error
            # Get-Item -Path 'C:\MayNotExist.txt'
            #
            # # Restore the former error preference
            # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
            #
            # # Retrieve the newest error on the error stack
            # if ($Error.Count -gt 0) {
            #     $refNewestCurrentError = ([ref]($Error[0]))
            # } else {
            #     $refNewestCurrentError = ([ref]$null)
            # }
            #
            # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
            #     # Error occurred
            # } else {
            #     # No error occurred
            # }
            #
            # .INPUTS
            # None. You can't pipe objects to Test-ErrorOccurred.
            #
            # .OUTPUTS
            # System.Boolean. Test-ErrorOccurred returns a boolean value
            # indicating whether an error occurred during the time period in
            # question. $true indicates an error occurred; $false indicates no
            # error occurred.
            #
            # .NOTES
            # This function also supports the use of positional parameters
            # instead of named parameters. If positional parameters are used
            # instead of named parameters, then two positional parameters are
            # required:
            #
            # The first positional parameter is a reference (memory pointer) to
            # a System.Management.Automation.ErrorRecord that represents the
            # newest error on the stack earlier in time, i.e., prior to running
            # the command for which you wish to determine whether an error
            # occurred. If no error was on the stack at this time, the first
            # positional parameter must be a reference to $null ([ref]$null).
            #
            # The second positional parameter is a reference (memory pointer)
            # to a System.Management.Automation.ErrorRecord that represents the
            # newest error on the stack later in time, i.e., after running
            # the command for which you wish to determine whether an error
            # occurred. If no error was on the stack at this time,
            # ReferenceToLaterError must be a reference to $null ([ref]$null).
            #
            # Version: 2.0.20260313.0

            param (
                [ref]$ReferenceToEarlierError = ([ref]$null),
                [ref]$ReferenceToLaterError = ([ref]$null)
            )

            #region License ################################################
            # Copyright (c) 2025 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person
            # obtaining a copy of this software and associated documentation
            # files (the "Software"), to deal in the Software without
            # restriction, including without limitation the rights to use,
            # copy, modify, merge, publish, distribute, sublicense, and/or sell
            # copies of the Software, and to permit persons to whom the
            # Software is furnished to do so, subject to the following
            # conditions:
            #
            # The above copyright notice and this permission notice shall be
            # included in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
            # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
            # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
            # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
            # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
            # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
            # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
            # OTHER DEALINGS IN THE SOFTWARE.
            #endregion License ################################################

            $boolErrorOccurred = $false
            if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                # Both not $null
                if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            } else {
                # One is $null, or both are $null
                # NOTE: $ReferenceToEarlierError could be non-null, while
                # $ReferenceToLaterError could be null if $error was cleared;
                # this does not indicate an error.
                # So:
                # - If both are null, no error.
                # - If $ReferenceToEarlierError is null and
                #   $ReferenceToLaterError is non-null, error.
                # - If $ReferenceToEarlierError is non-null and
                #   $ReferenceToLaterError is null, no error.
                if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    $boolErrorOccurred = $true
                }
            }

            return $boolErrorOccurred
        }
        #endregion FunctionsToSupportErrorHandling ####################################

        #region HelperFunctions ####################################################
        function Test-FileExistence {
            # .SYNOPSIS
            # Tests whether a file exists at the specified path.
            #
            # .DESCRIPTION
            # This helper function checks whether a file exists at the specified path using
            # .NET Framework methods to ensure cross-platform compatibility. The function
            # returns a boolean value indicating the file's existence. If an error occurs
            # during the check, the function returns $false.
            #
            # .PARAMETER Path
            # This parameter is required; it is a string representing the file path to
            # test.
            #
            # .EXAMPLE
            # $boolExists = Test-FileExistence -Path 'C:\Temp\test.txt'
            # if ($boolExists) {
            #     Write-Host 'File exists'
            # } else {
            #     Write-Host 'File does not exist'
            # }
            #
            # .EXAMPLE
            # $boolExists = Test-FileExistence 'C:\Temp\test.txt'
            # # Demonstrates using positional parameters. The positional parameter is the
            # # file path.
            #
            # .INPUTS
            # None. You can't pipe objects to Test-FileExistence.
            #
            # .OUTPUTS
            # System.Boolean. Test-FileExistence returns a boolean value indicating whether
            # the file exists. $true means the file exists. $false means the file does not
            # exist or an error occurred during the check.
            #
            # .NOTES
            # This function supports Windows PowerShell 1.0 with .NET Framework 2.0 or
            # newer, newer versions of Windows PowerShell (at least up to and including
            # Windows PowerShell 5.1 with .NET Framework 4.8 or newer), PowerShell Core
            # 6.x, and PowerShell 7.x. This function supports Windows and, when run on
            # PowerShell Core 6.x or PowerShell 7.x, also supports macOS and Linux.
            #
            # This function also supports the use of positional parameters instead of
            # named parameters. If positional parameters are used instead of named
            # parameters, then one positional parameter is required:
            #
            # The first positional parameter is a string representing the file path.
            #
            # Version: 1.0.20260313.0

            param (
                [string]$Path
            )

            #region License ########################################################
            # Copyright (c) 2026 Frank Lesniak
            #
            # Permission is hereby granted, free of charge, to any person obtaining a
            # copy of this software and associated documentation files (the
            # "Software"), to deal in the Software without restriction, including
            # without limitation the rights to use, copy, modify, merge, publish,
            # distribute, sublicense, and/or sell copies of the Software, and to
            # permit persons to whom the Software is furnished to do so, subject to
            # the following conditions:
            #
            # The above copyright notice and this permission notice shall be included
            # in all copies or substantial portions of the Software.
            #
            # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
            # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
            # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
            # IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
            # CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
            # TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
            # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
            #endregion License ########################################################

            #region FunctionsToSupportErrorHandling ####################################
            function Get-ReferenceToLastError {
                # .SYNOPSIS
                # Gets a reference (memory pointer) to the last error that
                # occurred.
                #
                # .DESCRIPTION
                # Returns a reference (memory pointer) to $null ([ref]$null) if no
                # errors on the $error stack; otherwise, returns a reference to
                # the last error that occurred.
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating
                # # errors from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work:
                # $refLastKnownError = Get-ReferenceToLastError
                #
                # # Store current error preference; we will restore it after we do
                # # some work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will
                # # suppress error output. Terminating errors will not output
                # # anything, kick to the empty trap statement and then continue
                # # on. Likewise, non-terminating errors will also not output
                # # anything, but they do not kick to the trap statement; they
                # # simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # $refNewestCurrentError = Get-ReferenceToLastError
                #
                # $boolErrorOccurred = $false
                # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #     # Both not $null
                #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # } else {
                #     # One is $null, or both are $null
                #     # NOTE: $refLastKnownError could be non-null, while
                #     # $refNewestCurrentError could be null if $error was cleared;
                #     # this does not indicate an error.
                #     #
                #     # So:
                #     # If both are null, no error.
                #     # If $refLastKnownError is null and $refNewestCurrentError is
                #     # non-null, error.
                #     # If $refLastKnownError is non-null and
                #     # $refNewestCurrentError is null, no error.
                #     #
                #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
                #         $boolErrorOccurred = $true
                #     }
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Get-ReferenceToLastError.
                #
                # .OUTPUTS
                # System.Management.Automation.PSReference ([ref]).
                # Get-ReferenceToLastError returns a reference (memory pointer) to
                # the last error that occurred. It returns a reference to $null
                # ([ref]$null) if there are no errors on the $error stack.
                #
                # .NOTES
                # This function accepts no parameters.
                #
                # This function is compatible with Windows PowerShell 1.0+ (with
                # .NET Framework 2.0 or newer), PowerShell Core 6.x, and PowerShell
                # 7.x on Windows, macOS, and Linux.
                #
                # Design Note: This function returns a [ref] object directly rather
                # than following the author's standard v1.0 pattern of returning an
                # integer status code. This design is intentional, as the
                # function's sole purpose is to provide a reference for error
                # tracking. Requiring a [ref] parameter would add unnecessary
                # complexity to the calling pattern.
                #
                # Version: 2.0.20260313.0

                param()

                #region License ################################################
                # Copyright (c) 2025 Frank Lesniak
                #
                # Permission is hereby granted, free of charge, to any person
                # obtaining a copy of this software and associated documentation
                # files (the "Software"), to deal in the Software without
                # restriction, including without limitation the rights to use,
                # copy, modify, merge, publish, distribute, sublicense, and/or sell
                # copies of the Software, and to permit persons to whom the
                # Software is furnished to do so, subject to the following
                # conditions:
                #
                # The above copyright notice and this permission notice shall be
                # included in all copies or substantial portions of the Software.
                #
                # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
                # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
                # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
                # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
                # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
                # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
                # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
                # OTHER DEALINGS IN THE SOFTWARE.
                #endregion License ################################################

                if ($Error.Count -gt 0) {
                    return ([ref]($Error[0]))
                } else {
                    return ([ref]$null)
                }
            }

            function Test-ErrorOccurred {
                # .SYNOPSIS
                # Checks to see if an error occurred during a time period, i.e.,
                # during the execution of a command.
                #
                # .DESCRIPTION
                # Using two references (memory pointers) to errors, this function
                # checks to see if an error occurred based on differences between
                # the two errors.
                #
                # To use this function, you must first retrieve a reference to the
                # last error that occurred prior to the command you are about to
                # run. Then, run the command. After the command completes, retrieve
                # a reference to the last error that occurred. Pass these two
                # references to this function to determine if an error occurred.
                #
                # .PARAMETER ReferenceToEarlierError
                # This parameter is required; it is a reference (memory pointer) to
                # a System.Management.Automation.ErrorRecord that represents the
                # newest error on the stack earlier in time, i.e., prior to running
                # the command for which you wish to determine whether an error
                # occurred.
                #
                # If no error was on the stack at this time,
                # ReferenceToEarlierError must be a reference to $null
                # ([ref]$null).
                #
                # .PARAMETER ReferenceToLaterError
                # This parameter is required; it is a reference (memory pointer) to
                # a System.Management.Automation.ErrorRecord that represents the
                # newest error on the stack later in time, i.e., after running
                # the command for which you wish to determine whether an error
                # occurred.
                #
                # If no error was on the stack at this time, ReferenceToLaterError
                # must be a reference to $null ([ref]$null).
                #
                # .EXAMPLE
                # # Intentionally empty trap statement to prevent terminating
                # # errors from halting processing
                # trap { }
                #
                # # Retrieve the newest error on the stack prior to doing work
                # if ($Error.Count -gt 0) {
                #     $refLastKnownError = ([ref]($Error[0]))
                # } else {
                #     $refLastKnownError = ([ref]$null)
                # }
                #
                # # Store current error preference; we will restore it after we do
                # # some work:
                # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
                #
                # # Set ErrorActionPreference to SilentlyContinue; this will
                # # suppress error output. Terminating errors will not output
                # # anything, kick to the empty trap statement and then continue
                # # on. Likewise, non-terminating errors will also not output
                # # anything, but they do not kick to the trap statement; they
                # # simply continue on.
                # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                #
                # # Do something that might trigger an error
                # Get-Item -Path 'C:\MayNotExist.txt'
                #
                # # Restore the former error preference
                # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
                #
                # # Retrieve the newest error on the error stack
                # if ($Error.Count -gt 0) {
                #     $refNewestCurrentError = ([ref]($Error[0]))
                # } else {
                #     $refNewestCurrentError = ([ref]$null)
                # }
                #
                # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                #     # Error occurred
                # } else {
                #     # No error occurred
                # }
                #
                # .INPUTS
                # None. You can't pipe objects to Test-ErrorOccurred.
                #
                # .OUTPUTS
                # System.Boolean. Test-ErrorOccurred returns a boolean value
                # indicating whether an error occurred during the time period in
                # question. $true indicates an error occurred; $false indicates no
                # error occurred.
                #
                # .NOTES
                # This function supports Windows PowerShell 1.0 with .NET Framework
                # 2.0 or newer, newer versions of Windows PowerShell (at least up
                # to and including Windows PowerShell 5.1 with .NET Framework 4.8
                # or newer), PowerShell Core 6.x, and PowerShell 7.x. This function
                # supports Windows and, when run on PowerShell Core 6.x or
                # PowerShell 7.x, also supports macOS and Linux.
                #
                # This function also supports the use of positional parameters
                # instead of named parameters. If positional parameters are used
                # instead of named parameters, then two positional parameters are
                # required:
                #
                # The first positional parameter is a reference (memory pointer) to
                # a System.Management.Automation.ErrorRecord that represents the
                # newest error on the stack earlier in time, i.e., prior to running
                # the command for which you wish to determine whether an error
                # occurred. If no error was on the stack at this time, the first
                # positional parameter must be a reference to $null ([ref]$null).
                #
                # The second positional parameter is a reference (memory pointer)
                # to a System.Management.Automation.ErrorRecord that represents the
                # newest error on the stack later in time, i.e., after running
                # the command for which you wish to determine whether an error
                # occurred. If no error was on the stack at this time,
                # ReferenceToLaterError must be a reference to $null ([ref]$null).
                #
                # Version: 2.0.20260313.0

                param (
                    [ref]$ReferenceToEarlierError = ([ref]$null),
                    [ref]$ReferenceToLaterError = ([ref]$null)
                )

                #region License ################################################
                # Copyright (c) 2025 Frank Lesniak
                #
                # Permission is hereby granted, free of charge, to any person
                # obtaining a copy of this software and associated documentation
                # files (the "Software"), to deal in the Software without
                # restriction, including without limitation the rights to use,
                # copy, modify, merge, publish, distribute, sublicense, and/or sell
                # copies of the Software, and to permit persons to whom the
                # Software is furnished to do so, subject to the following
                # conditions:
                #
                # The above copyright notice and this permission notice shall be
                # included in all copies or substantial portions of the Software.
                #
                # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
                # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
                # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
                # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
                # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
                # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
                # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
                # OTHER DEALINGS IN THE SOFTWARE.
                #endregion License ################################################

                $boolErrorOccurred = $false
                if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                    # Both not $null
                    if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                        $boolErrorOccurred = $true
                    }
                } else {
                    # One is $null, or both are $null
                    # NOTE: $ReferenceToEarlierError could be non-null, while
                    # $ReferenceToLaterError could be null if $error was cleared;
                    # this does not indicate an error.
                    # So:
                    # - If both are null, no error.
                    # - If $ReferenceToEarlierError is null and
                    #   $ReferenceToLaterError is non-null, error.
                    # - If $ReferenceToEarlierError is non-null and
                    #   $ReferenceToLaterError is null, no error.
                    if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                        $boolErrorOccurred = $true
                    }
                }

                return $boolErrorOccurred
            }
            #endregion FunctionsToSupportErrorHandling ####################################

            trap {
                # Intentionally left empty to prevent terminating errors from halting
                # processing
            }

            # Validate input
            if ([string]::IsNullOrEmpty($Path)) {
                return $false
            }

            # Retrieve the newest error on the stack prior to doing work
            $refLastKnownError = Get-ReferenceToLastError

            # Store current error preference; we will restore it after we do the work of
            # this function
            $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

            # Set ErrorActionPreference to SilentlyContinue; this will suppress error
            # output. Terminating errors will not output anything, kick to the empty trap
            # statement and then continue on. Likewise, non-terminating errors will also
            # not output anything, but they do not kick to the trap statement; they simply
            # continue on.
            $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

            # Check if file exists using .NET method
            $boolFileExists = [System.IO.File]::Exists($Path)

            # Restore the former error preference
            $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

            # Retrieve the newest error on the error stack
            $refNewestCurrentError = Get-ReferenceToLastError

            if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
                # Error occurred
                return $false
            } else {
                # No error occurred
                return $boolFileExists
            }
        }
        #endregion HelperFunctions ####################################################

        trap {
            # Intentionally left empty to prevent terminating errors from halting
            # processing
        }

        # Validate input
        if ([string]::IsNullOrEmpty($Path)) {
            return -1
        }

        # Check if file exists before attempting deletion
        $boolFileExists = Test-FileExistence -Path $Path

        if ($boolFileExists -eq $false) {
            # File does not exist; treat as success
            $ReferenceToErrorRecord.Value = $null
            return 0
        }

        # File exists; attempt to delete it
        # Retrieve the newest error on the stack prior to doing work
        $refLastKnownError = Get-ReferenceToLastError

        # Store current error preference
        $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

        # Set ErrorActionPreference to SilentlyContinue
        $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

        # Attempt to delete the file using .NET method
        [System.IO.File]::Delete($Path)

        # Restore the former error preference
        $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

        # Retrieve the newest error on the error stack
        $refNewestCurrentError = Get-ReferenceToLastError

        if (Test-ErrorOccurred $refLastKnownError $refNewestCurrentError) {
            # Error occurred
            $ReferenceToErrorRecord.Value = $refNewestCurrentError.Value
            return -1
        } else {
            # No error occurred
            $ReferenceToErrorRecord.Value = $null
            return 0
        }
    }
    #endregion HelperFunctions ####################################################

    $boolWriteErrorOnFailure = $false
    $boolWriteWarningOnFailure = $false
    if ($null -ne $WriteErrorOnFailure) {
        if ($WriteErrorOnFailure.IsPresent -eq $true) {
            $boolWriteErrorOnFailure = $true
        }
    }
    if (-not $boolWriteErrorOnFailure) {
        if ($null -ne $WriteWarningOnFailure) {
            if ($WriteWarningOnFailure.IsPresent -eq $true) {
                $boolWriteWarningOnFailure = $true
            }
        }
    }

    # Validate input
    if ([string]::IsNullOrEmpty($Path)) {
        if ($boolWriteErrorOnFailure) {
            Write-Error 'The Path parameter is required and cannot be empty.'
        } elseif ($boolWriteWarningOnFailure) {
            Write-Warning 'The Path parameter is required and cannot be empty.'
        }
        return $false
    }

    # Initialize error record reference
    $errRecord = $null

    # Attempt to create the file
    $intReturnCode = New-File -Path $Path -ReferenceToErrorRecord ([ref]$errRecord)

    if ($intReturnCode -ne 0) {
        # File creation failed
        $ReferenceToErrorRecord.Value = $errRecord

        if ($boolWriteErrorOnFailure) {
            if ($null -ne $errRecord) {
                Write-Error ("Cannot write to file path '{0}'. The file may be open in another application, the path may be invalid, or you may not have sufficient permissions. Error: {1}" -f $Path, $errRecord.Exception.Message)
            } else {
                Write-Error ("Cannot write to file path '{0}'. The file may be open in another application, the path may be invalid, or you may not have sufficient permissions." -f $Path)
            }
        } elseif ($boolWriteWarningOnFailure) {
            if ($null -ne $errRecord) {
                Write-Warning ("Cannot write to file path '{0}'. The file may be open in another application, the path may be invalid, or you may not have sufficient permissions. Error: {1}" -f $Path, $errRecord.Exception.Message)
            } else {
                Write-Warning ("Cannot write to file path '{0}'. The file may be open in another application, the path may be invalid, or you may not have sufficient permissions." -f $Path)
            }
        }

        return $false
    }

    # File created successfully; now attempt to delete it
    $intReturnCode = Remove-File -Path $Path -ReferenceToErrorRecord ([ref]$errRecord)

    if ($intReturnCode -ne 0) {
        # File deletion failed; this is still considered a write failure
        # Best-effort cleanup: try one more time to delete
        $intReturnCode = Remove-File -Path $Path -ReferenceToErrorRecord ([ref]$errRecord)

        $ReferenceToErrorRecord.Value = $errRecord

        if ($boolWriteErrorOnFailure) {
            if ($null -ne $errRecord) {
                Write-Error ("Cannot write to file path '{0}'. The test file was created but could not be deleted. Error: {1}" -f $Path, $errRecord.Exception.Message)
            } else {
                Write-Error ("Cannot write to file path '{0}'. The test file was created but could not be deleted." -f $Path)
            }
        } elseif ($boolWriteWarningOnFailure) {
            if ($null -ne $errRecord) {
                Write-Warning ("Cannot write to file path '{0}'. The test file was created but could not be deleted. Error: {1}" -f $Path, $errRecord.Exception.Message)
            } else {
                Write-Warning ("Cannot write to file path '{0}'. The test file was created but could not be deleted." -f $Path)
            }
        }

        return $false
    }

    # Success: file was created and deleted
    $ReferenceToErrorRecord.Value = $null

    return $true
}

function Get-ADObjectSafely {
    # .SYNOPSIS
    # Safely retrieves an AD object using v1.0-compatible error handling.
    #
    # .DESCRIPTION
    # Wraps Get-ADObject in a v1.0-compatible error handling pattern
    # using trap and error reference comparison instead of try/catch.
    # On success, populates the reference parameter with the AD object
    # and returns 0. On failure, returns -1.
    #
    # .PARAMETER ReferenceToADObject
    # This parameter is required; it is a reference to a variable that
    # will be used to store the retrieved AD object on success. On
    # failure, it is set to $null.
    #
    # .PARAMETER Server
    # This parameter is required; it is a string representing the AD
    # server (DNS name) to query. Must be non-empty when supplied.
    #
    # .PARAMETER Identity
    # This parameter is required; it is a string representing the
    # distinguished name of the AD object to retrieve. Must be
    # non-empty when supplied.
    #
    # .PARAMETER Properties
    # This parameter is optional; it is an array of strings
    # representing additional properties to retrieve. When omitted or
    # empty, Get-ADObject returns only its default properties.
    #
    # .PARAMETER PSVersion
    # This parameter is optional; if supplied, it must be the version
    # number of the running version of PowerShell. If the version of
    # PowerShell is already known, it can be passed in to this function
    # to avoid the overhead of unnecessarily determining the version of
    # PowerShell. If this parameter is not supplied, the function will
    # determine the version of PowerShell that is running as part of
    # its processing.
    #
    # .EXAMPLE
    # $objADObject = $null
    # $intReturnCode = Get-ADObjectSafely -ReferenceToADObject ([ref]$objADObject) -Server 'contoso.com' -Identity 'OU=Sales,DC=contoso,DC=com' -Properties @('CanonicalName', 'nTSecurityDescriptor')
    # if ($intReturnCode -eq 0) {
    #     # $objADObject contains the retrieved AD object
    # }
    #
    # .EXAMPLE
    # $objADObject = $null
    # $intReturnCode = Get-ADObjectSafely ([ref]$objADObject) 'contoso.com' 'OU=Sales,DC=contoso,DC=com' @('CanonicalName', 'nTSecurityDescriptor')
    # # Demonstrates using positional parameters
    #
    # .EXAMPLE
    # $versionPS = Get-PSVersion
    # $objADObject = $null
    # $intReturnCode = Get-ADObjectSafely -ReferenceToADObject ([ref]$objADObject) -Server 'contoso.com' -Identity 'OU=Sales,DC=contoso,DC=com' -Properties @('CanonicalName', 'nTSecurityDescriptor') -PSVersion $versionPS
    # # Passes the already-known PowerShell version to skip redundant
    # # version detection within the function.
    #
    # .INPUTS
    # None. You can't pipe objects to Get-ADObjectSafely.
    #
    # .OUTPUTS
    # System.Int32. Get-ADObjectSafely returns an integer status code.
    # 0 means success; the AD object was retrieved and stored in the
    # reference parameter. -1 means failure; the AD object could not
    # be retrieved (or — on PowerShell 7.x — the ActiveDirectory
    # module could not be loaded via the Windows PowerShell
    # Compatibility layer).
    #
    # .NOTES
    # This function also supports the use of positional parameters
    # instead of named parameters. If positional parameters are used
    # instead of named parameters, then three to five positional
    # parameters are accepted:
    #
    # The first positional parameter is a required reference to a
    # variable that will be used to store the retrieved AD object on
    # success.
    #
    # The second positional parameter is a required string representing
    # the AD server (DNS name) to query.
    #
    # The third positional parameter is a required string representing
    # the distinguished name of the AD object to retrieve.
    #
    # The fourth positional parameter is an optional array of strings
    # representing additional properties to retrieve.
    #
    # The fifth positional parameter is an optional [version] object
    # representing the version of PowerShell. If supplied, the function
    # skips its own version detection.
    #
    # This function's design target is Windows PowerShell 1.0 with .NET
    # Framework 2.0 or newer, through Windows PowerShell 5.1 with .NET
    # Framework 4.8 or newer, and PowerShell 7.x on Windows (via the
    # Windows PowerShell Compatibility layer). Windows only.
    #
    # PowerShell Core 6.x is not expected to function because the RSAT
    # ActiveDirectory module is a Windows PowerShell module that requires
    # the Windows PowerShell Compatibility layer, which is available in
    # PowerShell 7.x but not in PowerShell Core 6.x. Additionally, even
    # after the planned migration to System.DirectoryServices .NET
    # classes, PowerShell Core 6.x will remain unsupported because it
    # runs on .NET Core 2.x, which does not include
    # System.DirectoryServices by default.
    #
    # This function currently requires PowerShell v2.0+ and the RSAT
    # ActiveDirectory module.
    #
    # Version: 1.1.20260316.0

    param (
        [ref]$ReferenceToADObject = ([ref]$null),
        [string]$Server = '',
        [string]$Identity = '',
        [string[]]$Properties = @(),
        [version]$PSVersion = ([version]'0.0')
    )

    #region ValidateInput #####################################################
    if ($Server -eq '') {
        # Server is required but was not supplied or was empty
        $ReferenceToADObject.Value = $null
        return -1
    }
    if ($Identity -eq '') {
        # Identity is required but was not supplied or was empty
        $ReferenceToADObject.Value = $null
        return -1
    }
    #endregion ValidateInput #####################################################

    #region PowerShell version detection and ActiveDirectory module import #####
    # Detect the running PowerShell version inline (same logic as
    # Get-PSVersion) to avoid defining a nested function on every call.
    # If the caller already provided -PSVersion, use that instead.
    $versionPS = $PSVersion
    if ($null -eq $versionPS -or $versionPS -eq ([version]'0.0')) {
        if (Test-Path variable:\PSVersionTable) {
            $versionPS = $PSVersionTable.PSVersion
        } else {
            $versionPS = [version]('1.0')
        }
    }

    if ($versionPS.Major -ge 7) {
        if ($null -eq (Get-Module -Name ActiveDirectory)) {
            Import-Module -Name ActiveDirectory -UseWindowsPowerShell -ErrorAction SilentlyContinue
            if ($null -eq (Get-Module -Name ActiveDirectory)) {
                Write-Warning -Message 'The ActiveDirectory module could not be loaded. On PowerShell 7.x, this module is imported via the Windows PowerShell Compatibility layer. Ensure RSAT (Remote Server Administration Tools) is installed and the ActiveDirectory module is available in Windows PowerShell.'
                $ReferenceToADObject.Value = $null
                return -1
            }
        }
    }
    #endregion PowerShell version detection and ActiveDirectory module import ##

    #region FunctionsToSupportErrorHandling ####################################
    function Get-ReferenceToLastError {
        # .SYNOPSIS
        # Gets a reference (memory pointer) to the last error that
        # occurred.
        #
        # .DESCRIPTION
        # Returns a reference (memory pointer) to $null ([ref]$null) if no
        # errors on the $error stack; otherwise, returns a reference to
        # the last error that occurred.
        #
        # .EXAMPLE
        # # Intentionally empty trap statement to prevent terminating
        # # errors from halting processing
        # trap { }
        #
        # # Retrieve the newest error on the stack prior to doing work:
        # $refLastKnownError = Get-ReferenceToLastError
        #
        # # Store current error preference; we will restore it after we do
        # # some work:
        # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
        #
        # # Set ErrorActionPreference to SilentlyContinue; this will
        # # suppress error output. Terminating errors will not output
        # # anything, kick to the empty trap statement and then continue
        # # on. Likewise, non-terminating errors will also not output
        # # anything, but they do not kick to the trap statement; they
        # # simply continue on.
        # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
        #
        # # Do something that might trigger an error
        # Get-Item -Path 'C:\MayNotExist.txt'
        #
        # # Restore the former error preference
        # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
        #
        # # Retrieve the newest error on the error stack
        # $refNewestCurrentError = Get-ReferenceToLastError
        #
        # $boolErrorOccurred = $false
        # if (($null -ne $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
        #     # Both not $null
        #     if (($refLastKnownError.Value) -ne ($refNewestCurrentError.Value)) {
        #         $boolErrorOccurred = $true
        #     }
        # } else {
        #     # One is $null, or both are $null
        #     # NOTE: $refLastKnownError could be non-null, while
        #     # $refNewestCurrentError could be null if $error was cleared;
        #     # this does not indicate an error.
        #     #
        #     # So:
        #     # If both are null, no error.
        #     # If $refLastKnownError is null and $refNewestCurrentError is
        #     # non-null, error.
        #     # If $refLastKnownError is non-null and
        #     # $refNewestCurrentError is null, no error.
        #     #
        #     if (($null -eq $refLastKnownError.Value) -and ($null -ne $refNewestCurrentError.Value)) {
        #         $boolErrorOccurred = $true
        #     }
        # }
        #
        # .INPUTS
        # None. You can't pipe objects to Get-ReferenceToLastError.
        #
        # .OUTPUTS
        # System.Management.Automation.PSReference ([ref]).
        # Get-ReferenceToLastError returns a reference (memory pointer) to
        # the last error that occurred. It returns a reference to $null
        # ([ref]$null) if there are no errors on the $error stack.
        #
        # .NOTES
        # This function accepts no parameters.
        #
        # This function is compatible with Windows PowerShell 1.0+ (with
        # .NET Framework 2.0 or newer), PowerShell Core 6.x, and PowerShell
        # 7.x on Windows, macOS, and Linux.
        #
        # Design Note: This function returns a [ref] object directly rather
        # than following the author's standard v1.0 pattern of returning an
        # integer status code. This design is intentional, as the
        # function's sole purpose is to provide a reference for error
        # tracking. Requiring a [ref] parameter would add unnecessary
        # complexity to the calling pattern.
        #
        # Version: 2.0.20260313.0

        param()

        #region License ################################################
        # Copyright (c) 2025 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person
        # obtaining a copy of this software and associated documentation
        # files (the "Software"), to deal in the Software without
        # restriction, including without limitation the rights to use,
        # copy, modify, merge, publish, distribute, sublicense, and/or sell
        # copies of the Software, and to permit persons to whom the
        # Software is furnished to do so, subject to the following
        # conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
        # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
        # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
        # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
        # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
        # OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ################################################

        if ($Error.Count -gt 0) {
            return ([ref]($Error[0]))
        } else {
            return ([ref]$null)
        }
    }

    function Test-ErrorOccurred {
        # .SYNOPSIS
        # Checks to see if an error occurred during a time period, i.e.,
        # during the execution of a command.
        #
        # .DESCRIPTION
        # Using two references (memory pointers) to errors, this function
        # checks to see if an error occurred based on differences between
        # the two errors.
        #
        # To use this function, you must first retrieve a reference to the
        # last error that occurred prior to the command you are about to
        # run. Then, run the command. After the command completes, retrieve
        # a reference to the last error that occurred. Pass these two
        # references to this function to determine if an error occurred.
        #
        # .PARAMETER ReferenceToEarlierError
        # This parameter is required; it is a reference (memory pointer) to
        # a System.Management.Automation.ErrorRecord that represents the
        # newest error on the stack earlier in time, i.e., prior to running
        # the command for which you wish to determine whether an error
        # occurred.
        #
        # If no error was on the stack at this time,
        # ReferenceToEarlierError must be a reference to $null
        # ([ref]$null).
        #
        # .PARAMETER ReferenceToLaterError
        # This parameter is required; it is a reference (memory pointer) to
        # a System.Management.Automation.ErrorRecord that represents the
        # newest error on the stack later in time, i.e., after running
        # the command for which you wish to determine whether an error
        # occurred.
        #
        # If no error was on the stack at this time, ReferenceToLaterError
        # must be a reference to $null ([ref]$null).
        #
        # .EXAMPLE
        # # Intentionally empty trap statement to prevent terminating
        # # errors from halting processing
        # trap { }
        #
        # # Retrieve the newest error on the stack prior to doing work
        # if ($Error.Count -gt 0) {
        #     $refLastKnownError = ([ref]($Error[0]))
        # } else {
        #     $refLastKnownError = ([ref]$null)
        # }
        #
        # # Store current error preference; we will restore it after we do
        # # some work:
        # $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference
        #
        # # Set ErrorActionPreference to SilentlyContinue; this will
        # # suppress error output. Terminating errors will not output
        # # anything, kick to the empty trap statement and then continue
        # # on. Likewise, non-terminating errors will also not output
        # # anything, but they do not kick to the trap statement; they
        # # simply continue on.
        # $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
        #
        # # Do something that might trigger an error
        # Get-Item -Path 'C:\MayNotExist.txt'
        #
        # # Restore the former error preference
        # $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference
        #
        # # Retrieve the newest error on the error stack
        # if ($Error.Count -gt 0) {
        #     $refNewestCurrentError = ([ref]($Error[0]))
        # } else {
        #     $refNewestCurrentError = ([ref]$null)
        # }
        #
        # if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
        #     # Error occurred
        # } else {
        #     # No error occurred
        # }
        #
        # .INPUTS
        # None. You can't pipe objects to Test-ErrorOccurred.
        #
        # .OUTPUTS
        # System.Boolean. Test-ErrorOccurred returns a boolean value
        # indicating whether an error occurred during the time period in
        # question. $true indicates an error occurred; $false indicates no
        # error occurred.
        #
        # .NOTES
        # This function supports Windows PowerShell 1.0 with .NET Framework
        # 2.0 or newer, newer versions of Windows PowerShell (at least up
        # to and including Windows PowerShell 5.1 with .NET Framework 4.8
        # or newer), PowerShell Core 6.x, and PowerShell 7.x. This function
        # supports Windows and, when run on PowerShell Core 6.x or
        # PowerShell 7.x, also supports macOS and Linux.
        #
        # This function also supports the use of positional parameters
        # instead of named parameters. If positional parameters are used
        # instead of named parameters, then two positional parameters are
        # required:
        #
        # The first positional parameter is a reference (memory pointer) to
        # a System.Management.Automation.ErrorRecord that represents the
        # newest error on the stack earlier in time, i.e., prior to running
        # the command for which you wish to determine whether an error
        # occurred. If no error was on the stack at this time, the first
        # positional parameter must be a reference to $null ([ref]$null).
        #
        # The second positional parameter is a reference (memory pointer)
        # to a System.Management.Automation.ErrorRecord that represents the
        # newest error on the stack later in time, i.e., after running
        # the command for which you wish to determine whether an error
        # occurred. If no error was on the stack at this time,
        # ReferenceToLaterError must be a reference to $null ([ref]$null).
        #
        # Version: 2.0.20260313.0

        param (
            [ref]$ReferenceToEarlierError = ([ref]$null),
            [ref]$ReferenceToLaterError = ([ref]$null)
        )

        #region License ################################################
        # Copyright (c) 2025 Frank Lesniak
        #
        # Permission is hereby granted, free of charge, to any person
        # obtaining a copy of this software and associated documentation
        # files (the "Software"), to deal in the Software without
        # restriction, including without limitation the rights to use,
        # copy, modify, merge, publish, distribute, sublicense, and/or sell
        # copies of the Software, and to permit persons to whom the
        # Software is furnished to do so, subject to the following
        # conditions:
        #
        # The above copyright notice and this permission notice shall be
        # included in all copies or substantial portions of the Software.
        #
        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
        # OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
        # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
        # WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
        # FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
        # OTHER DEALINGS IN THE SOFTWARE.
        #endregion License ################################################

        $boolErrorOccurred = $false
        if (($null -ne $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
            # Both not $null
            if (($ReferenceToEarlierError.Value) -ne ($ReferenceToLaterError.Value)) {
                $boolErrorOccurred = $true
            }
        } else {
            # One is $null, or both are $null
            # NOTE: $ReferenceToEarlierError could be non-null, while
            # $ReferenceToLaterError could be null if $error was cleared;
            # this does not indicate an error.
            # So:
            # - If both are null, no error.
            # - If $ReferenceToEarlierError is null and
            #   $ReferenceToLaterError is non-null, error.
            # - If $ReferenceToEarlierError is non-null and
            #   $ReferenceToLaterError is null, no error.
            if (($null -eq $ReferenceToEarlierError.Value) -and ($null -ne $ReferenceToLaterError.Value)) {
                $boolErrorOccurred = $true
            }
        }

        return $boolErrorOccurred
    }
    #endregion FunctionsToSupportErrorHandling ####################################

    trap {
        # Intentionally left empty to prevent terminating errors from halting
        # processing
    }

    # Retrieve the newest error on the stack prior to doing work
    $refLastKnownError = Get-ReferenceToLastError

    # Store current error preference; we will restore it after we do the work of
    # this function
    $actionPreferenceFormerErrorPreference = $global:ErrorActionPreference

    # Set ErrorActionPreference to SilentlyContinue; this will suppress error
    # output. Terminating errors will not output anything, kick to the empty trap
    # statement and then continue on. Likewise, non-terminating errors will also
    # not output anything, but they do not kick to the trap statement; they simply
    # continue on.
    $global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    # Do the work of this function
    $objRetrievedADObject = Get-ADObject -Server $Server -Identity $Identity -Properties $Properties

    # Restore the former error preference
    $global:ErrorActionPreference = $actionPreferenceFormerErrorPreference

    # Retrieve the newest error on the error stack
    $refNewestCurrentError = Get-ReferenceToLastError

    if (Test-ErrorOccurred -ReferenceToEarlierError $refLastKnownError -ReferenceToLaterError $refNewestCurrentError) {
        # Error occurred; clear reference output and return failure
        $ReferenceToADObject.Value = $null
        return -1
    } else {
        # No error occurred
        $ReferenceToADObject.Value = $objRetrievedADObject
        return 0
    }
}
#endregion Functions

function Export-ADDSOUPermission {
    # .SYNOPSIS
    # Exports Active Directory Domain Services (AD DS) organizational unit (OU)
    # permissions to a CSV file.
    #
    # .DESCRIPTION
    # This function enumerates all organizational units (OUs) in the current
    # computer's Active Directory domain and exports their access control entries
    # (ACEs) to a CSV file. It also identifies and reports any unresolved GUIDs
    # found in the ACEs.
    #
    # .EXAMPLE
    # Export-ADDSOUPermission
    #
    # Runs the function and produces OUPermissions.csv and (if needed)
    # UnresolvedGUIDs.csv in the current directory.
    #
    # .EXAMPLE
    # $versionPS = Get-PSVersion
    # $intReturnCode = Export-ADDSOUPermission
    # if ($intReturnCode -eq 0) {
    #     $strMessage = 'Export completed successfully.'
    # } else {
    #     $strMessage = 'Export failed.'
    # }
    # if ($versionPS -ge ([version]'5.0')) {
    #     Write-Information -MessageData $strMessage -InformationAction Continue
    # } else {
    #     Write-Verbose -Message $strMessage -Verbose
    # }
    #
    # Demonstrates checking the return code and displaying a status message
    # using the version-conditional Write-Information / Write-Verbose
    # pattern. Returns 0 on success, -1 on failure (wrong OS, output
    # file not writable, or — on PowerShell 7.x — ActiveDirectory
    # module could not be loaded).
    #
    # .EXAMPLE
    # Export-ADDSOUPermission
    #
    # If unresolved GUIDs are found in OU ACEs (for example, from orphaned
    # schema extensions left behind by applications like Lync/Skype for
    # Business), the function creates UnresolvedGUIDs.csv in the current
    # directory, listing the GUID values that could not be resolved to
    # schema attributes or extended rights.
    #
    # .INPUTS
    # None. You can't pipe objects to this function.
    #
    # .OUTPUTS
    # [int] Status code:
    # 0 = success; OU permissions were exported to OUPermissions.csv, and
    # (if unresolved GUIDs were found) UnresolvedGUIDs.csv was also
    # created.
    # -1 = failure. Possible causes:
    #   - The script is not running on Windows (OS compatibility check
    #     failed).
    #   - The output file OUPermissions.csv is not writable at the
    #     current path.
    #   - The output file UnresolvedGUIDs.csv is not writable at the
    #     current path.
    #   - On PowerShell 7.x, the ActiveDirectory module could not be
    #     loaded via the Windows PowerShell Compatibility layer.
    #
    # .NOTES
    # This function does not accept parameters.
    #
    # This function's design target is Windows PowerShell 1.0 with .NET
    # Framework 2.0 or newer, through Windows PowerShell 5.1 with .NET
    # Framework 4.8 or newer, and PowerShell 7.x on Windows (via the
    # Windows PowerShell Compatibility layer). Windows only.
    #
    # PowerShell Core 6.x is not expected to function because the RSAT
    # ActiveDirectory module is a Windows PowerShell module that requires
    # the Windows PowerShell Compatibility layer, which is available in
    # PowerShell 7.x but not in PowerShell Core 6.x. Additionally, even
    # after the planned migration to System.DirectoryServices .NET
    # classes, PowerShell Core 6.x will remain unsupported because it
    # runs on .NET Core 2.x, which does not include
    # System.DirectoryServices by default.
    #
    # This function requires the ActiveDirectory PowerShell module.
    #
    # NOTE: This function currently depends on ActiveDirectory module cmdlets
    # (Get-ADDomain, Get-ADObject, Get-ADOrganizationalUnit, Get-ADRootDSE),
    # which require PowerShell v2.0+ and the RSAT ActiveDirectory module. A
    # planned migration will replace these cmdlets with
    # [System.DirectoryServices.DirectoryEntry] and
    # [System.DirectoryServices.DirectorySearcher] .NET classes (available in
    # .NET Framework 2.0), achieving true PowerShell v1.0 compatibility and
    # enabling the script to run on any domain member server without requiring
    # RSAT. This migration is tracked separately.
    #
    # Version: 1.1.20260316.1

    param()

    $strOutputFileOUPermissions = Join-Path -Path (Get-Location).Path -ChildPath 'OUPermissions.csv'
    $strOutputFileUnresolvedGUIDs = Join-Path -Path (Get-Location).Path -ChildPath 'UnresolvedGUIDs.csv'

    $versionPS = Get-PSVersion

    #region Preflight OS check
    $boolIsWindows = Test-Windows -PSVersion $versionPS
    if ($boolIsWindows -ne $true) {
        Write-Warning -Message 'This script requires Windows because it depends on Active Directory Domain Services. It cannot run on macOS or Linux.'
        return -1
    }
    #endregion Preflight OS check

    #region Preflight writeability checks
    $boolOutputFileWriteable = Test-FileWriteability -Path $strOutputFileOUPermissions -WriteWarningOnFailure
    if (-not $boolOutputFileWriteable) {
        return -1
    }
    $boolOutputFileWriteable = Test-FileWriteability -Path $strOutputFileUnresolvedGUIDs -WriteWarningOnFailure
    if (-not $boolOutputFileWriteable) {
        return -1
    }
    #endregion Preflight writeability checks

    #region Import ActiveDirectory module for PowerShell 7.x compatibility
    if ($versionPS.Major -ge 7) {
        Import-Module -Name ActiveDirectory -UseWindowsPowerShell -ErrorAction SilentlyContinue
        if ($null -eq (Get-Module -Name ActiveDirectory)) {
            Write-Warning -Message 'The ActiveDirectory module could not be loaded. On PowerShell 7.x, this module is imported via the Windows PowerShell Compatibility layer. Ensure RSAT (Remote Server Administration Tools) is installed and the ActiveDirectory module is available in Windows PowerShell.'
            return -1
        }
    }
    #endregion Import ActiveDirectory module for PowerShell 7.x compatibility

    # In a multi-domain forest, AD cmdlets can default to the *logged-on user's* domain.
    # Because you're running on a child-domain DC while using a parent-domain account,
    # Get-ADDomain can return the parent DN, while other cmdlets bind to the child DC.
    # Pin all queries to the domain of the computer running the script.

    # Pin every AD query in this script to the domain of the computer we're running on
    $objTargetDomain = Get-ADDomain -Current LocalComputer
    $strTargetDomainDN = $objTargetDomain.DistinguishedName
    $strTargetDomainDNS = $objTargetDomain.DNSRoot # valid value for -Server

    #region Build a list of objects for which we will gather permissions
    $listDistinguishedNamesToCheck = New-Object -TypeName 'System.Collections.Generic.List[string]'

    [void]($listDistinguishedNamesToCheck.Add($strTargetDomainDN))

    Get-ADOrganizationalUnit -Server $strTargetDomainDNS -SearchBase $strTargetDomainDN -Filter * |
        ForEach-Object {
            [void]($listDistinguishedNamesToCheck.Add($_.DistinguishedName))
        }
    #endregion Build a list of objects for which we will gather permissions

    #region Build a lookup table of GUID -> Friendly Name
    $hashtableSchemaIDGUIDsToName = @{}

    $strSchemaDistinguishedName = (Get-ADRootDSE -Server $strTargetDomainDNS).schemaNamingContext
    Get-ADObject -Server $strTargetDomainDNS -SearchBase $strSchemaDistinguishedName -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |
        ForEach-Object {
            $objThisSchemaEntry = $_
            $guidFromSchema = [System.GUID]$objThisSchemaEntry.schemaIDGUID
            if ($hashtableSchemaIDGUIDsToName.ContainsKey($guidFromSchema) -eq $false) {
                $hashtableSchemaIDGUIDsToName.Add($guidFromSchema, $objThisSchemaEntry.name)
            }
        }

    $strConfigurationDistinguishedName = (Get-ADRootDSE -Server $strTargetDomainDNS).configurationNamingContext
    $strExtendedRightsDistinguishedName = 'CN=Extended-Rights,' + $strConfigurationDistinguishedName

    Get-ADObject -Server $strTargetDomainDNS -SearchBase $strExtendedRightsDistinguishedName -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |
        ForEach-Object {
            $objThisExtendedRight = $_
            $guidFromExtendedRight = [System.GUID]$objThisExtendedRight.rightsGUID
            if ($hashtableSchemaIDGUIDsToName.ContainsKey($guidFromExtendedRight) -eq $false) {
                $hashtableSchemaIDGUIDsToName.Add($guidFromExtendedRight, $objThisExtendedRight.name)
            }
        }

    #endregion Build a lookup table of GUID -> Friendly Name
    #region Collect permissions and track unresolved GUIDs
    $listPermissions = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
    # Track unresolved GUIDs: key = GUID string, value = hashtable with field name and
    # list of DistinguishedNames where the GUID was encountered
    $hashtableUnresolvedGUIDs = @{}
    $arrAdditionalObjectPropertiesToRetrieve = @('CanonicalName', 'nTSecurityDescriptor')

    foreach ($strThisObjectDistinguishedName in $listDistinguishedNamesToCheck) {
        $objThisADObject = $null
        $intReturnCode = Get-ADObjectSafely -ReferenceToADObject ([ref]$objThisADObject) -Server $strTargetDomainDNS -Identity $strThisObjectDistinguishedName -Properties $arrAdditionalObjectPropertiesToRetrieve -PSVersion $versionPS
        if ($intReturnCode -ne 0) {
            $strErrorDetail = ''
            if ($Error.Count -gt 0) {
                $strErrorDetail = $Error[0].Exception.Message
            }
            if ($strErrorDetail -ne '') {
                Write-Warning -Message ("Skipping '{0}' because it could not be read from '{1}'. Error: {2}" -f $strThisObjectDistinguishedName, $strTargetDomainDNS, $strErrorDetail)
            } else {
                Write-Warning -Message ("Skipping '{0}' because it could not be read from '{1}'." -f $strThisObjectDistinguishedName, $strTargetDomainDNS)
            }
            continue
        }
        if ($null -eq $objThisADObject) { continue }

        $objThisADObject.nTSecurityDescriptor.Access |
            ForEach-Object {
                $objActiveDirectoryAccessRule = $_

                $objPermission = New-Object -TypeName PSObject

                $arrAdditionalObjectPropertiesToRetrieve | ForEach-Object {
                    $strThisProperty = $_
                    $strThisPropertyValue = $objThisADObject.PSObject.Properties | Where-Object { $_.Name -eq $strThisProperty } | ForEach-Object { $_.Value }
                    $objPermission | Add-Member -MemberType NoteProperty -Name $strThisProperty -Value $strThisPropertyValue
                }

                # Write DistinguishedName
                $objPermission | Add-Member -MemberType NoteProperty -Name 'DistinguishedName' -Value $strThisObjectDistinguishedName

                # Write AccessControlType
                $objPermission | Add-Member -MemberType NoteProperty -Name 'Allow/Deny' -Value $objActiveDirectoryAccessRule.AccessControlType.ToString()

                # Write InheritanceType
                $objPermission | Add-Member -MemberType NoteProperty -Name 'ToTheseObjectTargets' -Value $objActiveDirectoryAccessRule.InheritanceType.ToString()

                # Write InheritedObjectTypeName
                # inheritedObjectType can be $null for non-object-specific ACEs
                if ($null -eq $objActiveDirectoryAccessRule.InheritedObjectType -or
                    [System.Guid]$objActiveDirectoryAccessRule.InheritedObjectType -eq [System.Guid]::Empty) {
                    $strInheritedObjectTypeName = 'All'
                } else {
                    $guidInheritedObjectType = [System.Guid]$objActiveDirectoryAccessRule.InheritedObjectType
                    $strInheritedObjectTypeName = $hashtableSchemaIDGUIDsToName.Item($guidInheritedObjectType)
                    if ([string]::IsNullOrEmpty($strInheritedObjectTypeName)) {
                        $strInheritedObjectTypeName = 'UNRESOLVED: ' + $guidInheritedObjectType.ToString()
                        #region Track unresolved GUID for InheritedObjectType
                        $strUnresolvedKey = 'InheritedObjectType:' + $guidInheritedObjectType.ToString()
                        if ($hashtableUnresolvedGUIDs.ContainsKey($strUnresolvedKey) -eq $false) {
                            $hashtableUnresolvedGUIDs.Add($strUnresolvedKey, @{
                                    'GUID' = $guidInheritedObjectType.ToString()
                                    'Field' = 'InheritedObjectType'
                                    'DistinguishedNames' = (New-Object -TypeName 'System.Collections.Generic.List[string]')
                                })
                        }
                        [void]($hashtableUnresolvedGUIDs[$strUnresolvedKey]['DistinguishedNames'].Add($strThisObjectDistinguishedName))
                        #endregion Track unresolved GUID for InheritedObjectType
                    }
                }
                $objPermission | Add-Member -MemberType NoteProperty -Name 'ToTheseObjectTypes' -Value $strInheritedObjectTypeName

                # Write ActiveDirectoryRights
                $objPermission | Add-Member -MemberType NoteProperty -Name 'Permissions' -Value $objActiveDirectoryAccessRule.ActiveDirectoryRights.ToString()

                # Write ObjectTypeName
                # objectType can be $null for non-object-specific ACEs
                if ($null -eq $objActiveDirectoryAccessRule.ObjectType -or [System.Guid]$objActiveDirectoryAccessRule.ObjectType -eq [System.Guid]::Empty) {
                    $strObjectTypeName = 'All'
                } else {
                    $guidObjectType = [System.Guid]$objActiveDirectoryAccessRule.ObjectType
                    $strObjectTypeName = $hashtableSchemaIDGUIDsToName.Item($guidObjectType)
                    if ([string]::IsNullOrEmpty($strObjectTypeName)) {
                        $strObjectTypeName = 'UNRESOLVED: ' + $guidObjectType.ToString()
                        #region Track unresolved GUID for ObjectType
                        $strUnresolvedKey = 'ObjectType:' + $guidObjectType.ToString()
                        if ($hashtableUnresolvedGUIDs.ContainsKey($strUnresolvedKey) -eq $false) {
                            $hashtableUnresolvedGUIDs.Add($strUnresolvedKey, @{
                                    'GUID' = $guidObjectType.ToString()
                                    'Field' = 'ObjectType'
                                    'DistinguishedNames' = (New-Object -TypeName 'System.Collections.Generic.List[string]')
                                })
                        }
                        [void]($hashtableUnresolvedGUIDs[$strUnresolvedKey]['DistinguishedNames'].Add($strThisObjectDistinguishedName))
                        #endregion Track unresolved GUID for ObjectType
                    }
                }
                $objPermission | Add-Member -MemberType NoteProperty -Name 'Attribute' -Value $strObjectTypeName

                # Write IdentityReference
                $objPermission | Add-Member -MemberType NoteProperty -Name 'PermissionAssignee' -Value $objActiveDirectoryAccessRule.IdentityReference.ToString()

                # Write ObjectFlags
                $objPermission | Add-Member -MemberType NoteProperty -Name 'ObjectFlags' -Value $objActiveDirectoryAccessRule.ObjectFlags.ToString()

                # Write IsInherited
                $objPermission | Add-Member -MemberType NoteProperty -Name 'IsInherited' -Value $objActiveDirectoryAccessRule.IsInherited.ToString()

                # Write InheritanceFlags
                $objPermission | Add-Member -MemberType NoteProperty -Name 'InheritanceFlags' -Value $objActiveDirectoryAccessRule.InheritanceFlags.ToString()

                # Write PropagationFlags
                $objPermission | Add-Member -MemberType NoteProperty -Name 'PropagationFlags' -Value $objActiveDirectoryAccessRule.PropagationFlags.ToString()

                [void]($listPermissions.Add($objPermission))
            }
    }
    #endregion Collect permissions and track unresolved GUIDs
    #region Sort and export main permissions report
    $arrSortOrder = @()

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'CanonicalName')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'Allow/Deny')
    $hashtableSortProperty.Add('descending', $true)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'PermissionAssignee')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'ToTheseObjectTargets')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'ToTheseObjectTypes')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'Permissions')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'Attribute')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'ObjectFlags')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'IsInherited')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'InheritanceFlags')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $hashtableSortProperty = @{}
    $hashtableSortProperty.Add('expression', 'PropagationFlags')
    $hashtableSortProperty.Add('descending', $false)
    $arrSortOrder += $hashtableSortProperty

    $listPermissions |
        Sort-Object -Property $arrSortOrder |
        Export-Csv -Path $strOutputFileOUPermissions -NoTypeInformation
    #endregion Sort and export main permissions report
    #region Report unresolved GUIDs
    if ($hashtableUnresolvedGUIDs.Keys.Count -gt 0) {
        Write-Warning -Message ("Unresolved GUID Report: The following GUIDs were referenced in ACEs but do not correspond to any current schema attribute, property set, or extended right. These are likely orphaned from a previous application deployment (e.g., Lync/Skype for Business). Consider removing these ACEs using the original application's management tools or manually.")

        # Build the CSV output rows and display console summary
        $listUnresolvedGUIDReport = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
        $hashtableUnresolvedGUIDs.Keys | ForEach-Object {
            $strKey = $_
            $hashtableThisEntry = $hashtableUnresolvedGUIDs[$strKey]
            $strGUID = $hashtableThisEntry['GUID']
            $strField = $hashtableThisEntry['Field']
            $listDistinguishedNames = $hashtableThisEntry['DistinguishedNames']
            # Deduplicate DNs (same GUID can appear on the same object in multiple ACEs)
            $arrUniqueDistinguishedNames = @($listDistinguishedNames | Select-Object -Unique)

            $strMessage = ("GUID: {0} | Field: {1} | Found on {2} object(s):" -f $strGUID, $strField, $arrUniqueDistinguishedNames.Count)
            foreach ($strDN in $arrUniqueDistinguishedNames) {
                $strMessage += ("`n  - {0}" -f $strDN)
            }
            Write-Warning -Message $strMessage

            # Add one row per affected object for the CSV
            $arrUniqueDistinguishedNames | ForEach-Object {
                $objRow = New-Object -TypeName PSObject
                $objRow | Add-Member -MemberType NoteProperty -Name 'UnresolvedGUID' -Value $strGUID
                $objRow | Add-Member -MemberType NoteProperty -Name 'ACEField' -Value $strField
                $objRow | Add-Member -MemberType NoteProperty -Name 'DistinguishedName' -Value $_
                [void]($listUnresolvedGUIDReport.Add($objRow))
            }
        }

        # Export the unresolved GUIDs report
        $listUnresolvedGUIDReport |
            Sort-Object -Property 'UnresolvedGUID', 'ACEField', 'DistinguishedName' |
            Export-Csv -Path $strOutputFileUnresolvedGUIDs -NoTypeInformation

        $strMessage = ("Unresolved GUID details exported to: {0}`nMain permissions report exported to: {1}" -f $strOutputFileUnresolvedGUIDs, $strOutputFileOUPermissions)
        Write-Warning -Message $strMessage
    } else {
        $strMessage = ("All GUIDs in ACEs resolved successfully. No orphaned references found.`nPermissions report exported to: {0}" -f $strOutputFileOUPermissions)
        if ($versionPS -ge ([version]'5.0')) {
            Write-Information -MessageData $strMessage -InformationAction Continue
        } else {
            Write-Verbose -Message $strMessage -Verbose
        }
    }
    #endregion Report unresolved GUIDs

    return 0
}

[void](Export-ADDSOUPermission)
