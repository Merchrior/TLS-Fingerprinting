# pcap-sync.ps1
# Copies PCAP/PCAPNG files from local data folder to Kubernetes pod.
# Run:
# powershell -ExecutionPolicy Bypass -File .\pcap-sync.ps1
# Stop: Ctrl+C

$LOCAL_DATA_DIR = "C:\Users\ahmet\Downloads\proje\data"
$NAMESPACE = "tls-fingerprinting"
$APP_LABEL = "app=tls-app"
$REMOTE_DIR = "/app/data"

$copied = @{}

Write-Host "[PCAP-SYNC] Started."
Write-Host "   Local : $LOCAL_DATA_DIR"
Write-Host "   Pod   : namespace=${NAMESPACE}, label=${APP_LABEL}, remote=${REMOTE_DIR}"
Write-Host "   Stop  : Ctrl+C"
Write-Host ""

while ($true) {
    try {
        $podName = kubectl -n $NAMESPACE get pods -l $APP_LABEL -o jsonpath="{.items[0].metadata.name}" 2>$null

        if ([string]::IsNullOrWhiteSpace($podName)) {
            Write-Host "[WARN] Pod not found. Check namespace or label: $NAMESPACE / $APP_LABEL"
            Start-Sleep -Seconds 5
            continue
        }

        kubectl -n $NAMESPACE exec $podName -- mkdir -p $REMOTE_DIR 2>$null | Out-Null

        $files = Get-ChildItem -Path $LOCAL_DATA_DIR -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -like "live_capture_*.pcap" -or
                $_.Name -like "live_capture_*.pcapng"
            }

        foreach ($f in $files) {
            $fname = $f.Name
            $fsize = $f.Length

            if ($fsize -eq 0) {
                continue
            }

            if ($copied.ContainsKey($fname) -and $copied[$fname] -eq $fsize) {
                continue
            }

            if ((Get-Date) - $f.LastWriteTime -lt (New-TimeSpan -Seconds 2)) {
                continue
            }

            $sizeMb = [math]::Round(($fsize / 1MB), 2)
            Write-Host "[COPY] $fname ($sizeMb MB)"

            $remoteTarget = "${podName}:${REMOTE_DIR}/${fname}"

            Push-Location $LOCAL_DATA_DIR
            kubectl -n $NAMESPACE cp ".\$fname" "$remoteTarget"
            $copyExitCode = $LASTEXITCODE
            Pop-Location

            if ($copyExitCode -eq 0) {
                $copied[$fname] = $fsize
                Write-Host "   [OK] Copied to $remoteTarget"
            } else {
                Write-Host "   [ERROR] kubectl cp failed. Exit code: $copyExitCode"
            }
        }

        Start-Sleep -Seconds 2
    }
    catch {
        Write-Host "[ERROR] $($_.Exception.Message)"
        Start-Sleep -Seconds 5
    }
}