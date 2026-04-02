# AI Security Scanner - Node_modules 变更监控 (简化版)
# 使用 Windows Task Scheduler 的文件触发器

param(
    [string]$WatchPath = "D:\gitzone",
    [string]$ScannerScript = "D:\storagezone\lobsterai\skills\ai-security-scanner\auto_scanner.py",
    [string]$ReportDir = "D:\storagezone\lobsterai\skills\ai-security-scanner\reports"
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================"
Write-Host "AI Security Scanner - Node_modules 变更监控"
Write-Host "============================================================"
Write-Host "监控路径: $WatchPath"
Write-Host "按 Ctrl+C 停止"
Write-Host "============================================================"

# 创建文件系统监控器
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $WatchPath
$watcher.IncludeSubdirectories = $true
$watcher.Filter = "package.json"
$watcher.EnableRaisingEvents = $true

$lastScan = Get-Date
$scanInProgress = $false

# 定义变更检测
$changeDetected = {
    $filePath = $Event.SourceEventArgs.FullPath
    
    # 只监控 node_modules 中直接子包的 package.json
    # 格式: .../node_modules/<package-name>/package.json
    if ($filePath -match "node_modules[/\\][^/\\]+[/\\]package\.json$") {
        $global:changeDetected = $true
        $global:lastChangePath = $filePath
    }
}

# 定义错误处理
$errorOccurred = {
    Write-Host "[ERROR] 监控出错: $($Event.SourceEventArgs.Exception.Message)"
}

# 注册事件
$created = Register-ObjectEvent $watcher "Created" -Action $changeDetected -SourceIdentifier "PackageJsonCreated"
$changed = Register-ObjectEvent $watcher "Changed" -Action $changeDetected -SourceIdentifier "PackageJsonChanged"
$error = Register-ObjectEvent $watcher "Error" -Action $errorOccurred -SourceIdentifier "WatcherError"

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 开始监控 node_modules 变更..."

# 清理函数
function Cleanup {
    Write-Host "正在停止监控..."
    $watcher.EnableRaisingEvents = $false
    Unregister-Event -SourceIdentifier "PackageJsonCreated" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "PackageJsonChanged" -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier "WatcherError" -ErrorAction SilentlyContinue
    $watcher.Dispose()
    Write-Host "监控已停止"
}

# 注册清理
Register-EngineEvent -SourceIdentifier "PowerShell.Exiting" -Action { Cleanup } -MaxTriggerCount 1

try {
    while ($true) {
        Start-Sleep -Seconds 5
        
        if ($global:changeDetected -and -not $scanInProgress) {
            $global:changeDetected = $false
            $scanInProgress = $true
            
            $filePath = $global:lastChangePath
            Write-Host ""
            Write-Host "============================================================"
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 检测到 node_modules 变更"
            Write-Host "变更文件: $filePath"
            Write-Host "============================================================"
            
            # 等待 30 秒，让其他变更完成
            Start-Sleep -Seconds 30
            
            # 运行扫描
            $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $outputFile = Join-Path $ReportDir "node-change-scan-$timestamp.json"
            
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 运行安全扫描..."
            
            try {
                $env:PYTHONIOENCODING = "utf-8"
                $result = & python $ScannerScript -d $WatchPath -o $outputFile 2>&1
                
                Write-Host $result
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 扫描完成，未发现严重问题"
                } elseif ($LASTEXITCODE -eq 1) {
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 发现安全问题！"
                    Write-Host "报告: $outputFile"
                    
                    # 读取报告摘要
                    if (Test-Path $outputFile) {
                        $report = Get-Content $outputFile -Raw | ConvertFrom-Json
                        if ($report.security_issues.critical -gt 0) {
                            Write-Host "严重问题数: $($report.security_issues.critical)"
                        }
                    }
                }
            }
            catch {
                Write-Host "[ERROR] 扫描失败: $($_.Exception.Message)"
            }
            
            Write-Host ""
            $scanInProgress = $false
            $lastScan = Get-Date
        }
    }
}
catch [KeyboardInterrupt] {
    Write-Host ""
    Write-Host "收到停止信号"
}
finally {
    Cleanup
}
