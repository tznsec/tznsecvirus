param([string]$Out = "assets\tznsecvirus.ico")

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Drawing.Drawing2D -ErrorAction SilentlyContinue

$sizes = @(16, 24, 32, 48, 64, 128, 256)
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
$entries = @()

foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    $k = $s / 120.0
    function P($x, $y) { New-Object System.Drawing.PointF ([float]($x * $k)), ([float]($y * $k)) }

    $hex  = @((P 60 6), (P 107 33), (P 107 87), (P 60 114), (P 13 87), (P 13 33))
    $hex2 = @((P 60 17), (P 98 39), (P 98 81), (P 60 103), (P 22 81), (P 22 39))

    $pen2 = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(80, 0, 255, 156)), ([float]([Math]::Max(1, 1.5 * $k)))
    $g.DrawPolygon($pen2, [System.Drawing.PointF[]]$hex2)
    $pen2.Dispose()

    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 26, 68, 96)), ([float]([Math]::Max(1.5, 6 * $k)))
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $g.DrawPolygon($pen, [System.Drawing.PointF[]]$hex)
    $pen.Dispose()

    $defs = @(
        @{ cx = 60; cy = 45; r = 16.5; col = [System.Drawing.Color]::FromArgb(255, 0, 255, 156) },
        @{ cx = 43; cy = 77; r = 14.5; col = [System.Drawing.Color]::FromArgb(255, 0, 196, 122) },
        @{ cx = 77; cy = 77; r = 14.5; col = [System.Drawing.Color]::FromArgb(255, 53, 200, 255) }
    )
    foreach ($d in $defs) {
        $cx = [float]($d.cx * $k); $cy = [float]($d.cy * $k); $r = [float]($d.r * $k)
        $br = New-Object System.Drawing.SolidBrush $d.col
        $g.FillEllipse($br, [float]($cx - $r), [float]($cy - $r), [float](2 * $r), [float](2 * $r))
        $br.Dispose()
        # polysk
        $hr = [float]($r * 0.34)
        $hb = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(120, 255, 255, 255))
        $g.FillEllipse($hb, [float]($cx - $r * 0.48), [float]($cy - $r * 0.55), [float]($hr * 2), [float]($hr * 2))
        $hb.Dispose()
    }
    $g.Dispose()

    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bytes = $ms.ToArray()
    $ms.Dispose(); $bmp.Dispose()
    $entries += ,@{ size = $s; data = $bytes }
}

$fs = [System.IO.File]::Create($Out)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$entries.Count)
$offset = 6 + 16 * $entries.Count
foreach ($e in $entries) {
    $w = if ($e.size -ge 256) { 0 } else { $e.size }
    $bw.Write([byte]$w); $bw.Write([byte]$w); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([UInt16]1); $bw.Write([UInt16]32)
    $bw.Write([UInt32]$e.data.Length); $bw.Write([UInt32]$offset)
    $offset += $e.data.Length
}
foreach ($e in $entries) { $bw.Write($e.data) }
$bw.Flush(); $bw.Dispose(); $fs.Dispose()

Write-Host "ICO OK: $Out ($((Get-Item $Out).Length) bajtow, $($entries.Count) rozmiarow)"