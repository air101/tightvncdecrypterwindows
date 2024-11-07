# Define the decryption function
Function ConvertFrom-EncryptedVNCPassword {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [byte[]]
        $EncryptedData
    )
    
    # This is hardcoded in VNC applications like TightVNC.
    $magicKey = [byte[]]@(0xE8, 0x4A, 0xD6, 0x60, 0xC4, 0x72, 0x1A, 0xE0)
    $ansi = [System.Text.Encoding]::GetEncoding(
        [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
    
    if ($EncryptedData.Length -ne 8) {
        $err = [System.Management.Automation.ErrorRecord]::new(
            [ArgumentException]'Encrypted data must be 8 bytes long',
            'InvalidEncryptedLength',
            [System.Management.Automation.ErrorCategory]::InvalidArgument,
            $null)
        $PSCmdlet.WriteError($err)
        return
    }
    
    $des = $decryptor = $null
    try {
        $des = [System.Security.Cryptography.DES]::Create()
        $des.Padding = 'None'
        $decryptor = $des.CreateDecryptor($magicKey, [byte[]]::new(8))

        $data = [byte[]]::new(8)
        $null = $decryptor.TransformBlock($EncryptedData, 0, $EncryptedData.Length, $data, 0)
        
        $ansi.GetString($data).TrimEnd("`0")
    }
    finally {
        if ($decryptor) { $decryptor.Dispose() }
        if ($des) { $des.Dispose() }
    }
}

# Read the encrypted password from the registry
$regPath = "HKLM:\SOFTWARE\TightVNC\Server"
$regName = "Password"
$encryptedPassword = Get-ItemProperty -Path $regPath -Name $regName | Select-Object -ExpandProperty $regName

# Decrypt the password
$decryptedPassword = ConvertFrom-EncryptedVNCPassword -EncryptedData $encryptedPassword
Write-Output "Decrypted TightVNC Password: $decryptedPassword"
