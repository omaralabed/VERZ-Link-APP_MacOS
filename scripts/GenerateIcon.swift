import AppKit

let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for multiplier in [1, 2] {
        let pixels = size * multiplier
        let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        let context = NSGraphicsContext(bitmapImageRep: bitmap)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        let scale = CGFloat(pixels) / 100
        context.cgContext.scaleBy(x: scale, y: scale)
        let rect = NSRect(x: 5, y: 5, width: 90, height: 90)
        let background = NSBezierPath(roundedRect: rect, xRadius: 21, yRadius: 21)
        NSGradient(starting: NSColor(calibratedRed: 0.095, green: 0.14, blue: 0.17, alpha: 1),
                   ending: NSColor(calibratedRed: 0.025, green: 0.04, blue: 0.06, alpha: 1))!.draw(in: background, angle: -65)
        NSColor.white.withAlphaComponent(0.1).setStroke(); background.lineWidth = 0.6; background.stroke()
        let path = NSBezierPath()
        path.move(to: NSPoint(x: 23, y: 74)); path.line(to: NSPoint(x: 45, y: 26)); path.line(to: NSPoint(x: 56, y: 74))
        path.line(to: NSPoint(x: 78, y: 74)); path.line(to: NSPoint(x: 51, y: 26)); path.line(to: NSPoint(x: 78, y: 26))
        path.lineWidth = 6; path.lineCapStyle = .round; path.lineJoinStyle = .round
        NSColor(calibratedRed: 0.08, green: 0.91, blue: 0.74, alpha: 1).setStroke(); path.stroke()
        NSGraphicsContext.restoreGraphicsState()
        let suffix = multiplier == 2 ? "@2x" : ""
        let data = bitmap.representation(using: .png, properties: [:])!
        try data.write(to: output.appendingPathComponent("icon_\(size)x\(size)\(suffix).png"))
    }
}
